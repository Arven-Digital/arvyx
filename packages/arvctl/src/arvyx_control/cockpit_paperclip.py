"""Paperclip React distribution over the existing governed authority."""
from contextlib import closing
from pathlib import Path
import argparse
import json
import mimetypes
import os
import stat
from html.parser import HTMLParser
from threading import Lock
from urllib.parse import urlsplit
from . import safe_open
from .cockpit_web import DashboardHandler, DashboardServer, snapshot


class _BuildReferences(HTMLParser):
    """Entrypoint dependencies that must exist before publishing a generation."""
    def __init__(self):
        super().__init__()
        self.paths = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        value = attrs.get('src') if tag == 'script' else attrs.get('href') if tag == 'link' else None
        if value:
            url = urlsplit(value)
            if not url.scheme and not url.netloc:
                self.paths.add('/' + url.path.lstrip('/'))


def _read_regular(directory, name):
    # Descriptor-relative opens forbid symlink swaps, including parent directories.
    fd = safe_open.open_file_at(directory, name)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Not a regular frontend asset')
        data = stream.read()
        # Compare identity and content metadata only. Reading may update st_atime
        # (relatime: the first read after a write), which is not a content change.
        if _content_identity(before) != _content_identity(os.fstat(stream.fileno())) or len(data) != before.st_size:
            raise ValueError('Frontend build changed during capture')
        return data


def _content_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _capture_build(directory, prefix=''):
    files = {}
    with closing(safe_open.scandir_names(directory)) as names_iter:
        for name in names_iter:
            info = safe_open.stat_at(directory, name)
            path = prefix + '/' + name
            if stat.S_ISDIR(info.st_mode):
                fd = safe_open.open_directory_at(directory, name)
                try:
                    files.update(_capture_build(fd, path))
                finally:
                    os.close(fd)
            elif stat.S_ISREG(info.st_mode):
                files[path] = _read_regular(directory, name)
    return files


class PaperclipHandler(DashboardHandler):
    def send_header(self, keyword, value):
        if keyword.lower() == 'content-security-policy':
            value = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        super().send_header(keyword, value)

    def _primary(self, *, mutation=False):
        import sqlite3
        if (not self.authorized(mutation=mutation)
                or self.headers.get_all('Origin', []) not in ([], [self.server.origin])):
            return self.reply(403, {'error': 'Authenticated local human session required'})
        if self.server.primary is None:
            return self.reply(503, {'error': 'Primary authority unavailable'})
        try:
            if mutation:
                if self.headers.get_all('Content-Type', []) != ['application/json']:
                    raise ValueError('JSON required')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or self.headers.get('Transfer-Encoding') is not None:
                    raise ValueError('Unambiguous framing required')
                size = int(lengths[0])
                if not 0 < size <= 4096:
                    raise ValueError('Bounded body required')
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('Incomplete body')
                def unique(pairs):
                    result = dict(pairs)
                    if len(result) != len(pairs):
                        raise ValueError('Duplicate fields')
                    return result
                body = json.loads(raw, object_pairs_hook=unique)
                if (not isinstance(body, dict) or set(body) != {'agent_id', 'revision'}
                        or not isinstance(body['agent_id'], str) or type(body['revision']) is not int
                        or not 0 <= body['revision'] <= 9007199254740991):
                    raise ValueError('Exact selection envelope required')
                self.server.primary.select(body['agent_id'], revision=body['revision'])
            return self.reply(200, self.server.primary.read())
        except PermissionError:
            return self.reply(403, {'error': 'Human operator authority required'})
        except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
            return self.reply(409 if str(exc) == 'stale primary selection revision' else 400,
                              {'error': 'Stale revision; refresh' if str(exc) == 'stale primary selection revision' else 'Invalid primary selection request'})
        except (OSError, RuntimeError, sqlite3.Error):
            return self.reply(503, {'error': 'Primary authority unavailable; refresh before retrying'})

    def do_GET(self):
        if self.path == '/api/primary-agent':
            return self._primary()
        if self.path.startswith('/assets/') and self.path in {'/assets/favicon.png', '/assets/arvyx-wordmark.png'}:
            return super().do_GET()
        if self.path == '/api/snapshot':
            if not self.authorized():
                self.reply(403, {'error': 'Local capability required'})
                return
            try:
                local = snapshot(self.server.root)
                team = self.server.team.read() if self.server.team else {'availability': {}}
                self.reply(200, {'local': local, 'team': team})
            except (ValueError, OSError, RuntimeError):
                self.reply(503, {'error': 'Authority unavailable; no actions queued'})
            return
        # Only explicitly enumerated distribution paths; no traversal or SPA fallback.
        asset = self.server.frontend_asset(self.path)
        if asset is None:
            self.reply(404, {'error': 'Unknown frontend asset'})
            return
        self.reply(200, asset, content_type=mimetypes.guess_type(self.path)[0] or ('text/html' if self.path == '/' else 'application/octet-stream'))

    def do_POST(self):
        if self.path == '/api/primary-agent':
            return self._primary(mutation=True)
        # Reuse the exact origin/capability, bounded JSON and AMC permission gate.
        # Session control remains unavailable through this team-only surface.
        if self.path == '/api/team/action':
            return super().do_POST()
        self.reply(405, {'error': 'Only governed team actions are supported'})


class PaperclipServer(DashboardServer):
    def __init__(self, root, frontend, port=0, *, capability=None, team=None, primary=None):
        self.primary = primary
        if self.primary is None and team is not None:
            from .cockpit_primary import existing_native_primary
            try:
                self.primary = existing_native_primary(root, team)
            except (OSError, ValueError, RuntimeError):
                # Keep presentation available, but primary fails closed with 503.
                self.primary = None
        self.frontend = Path(frontend).absolute()
        self.frontend_files = {}
        self.previous_frontend_files = {}
        self.frontend_lock = Lock()
        try:
            self._refresh_frontend()
        except (OSError, ValueError) as error:
            raise ValueError('Build the Paperclip frontend first') from error
        super().__init__(root, port, capability=capability, team=team)
        self.RequestHandlerClass = PaperclipHandler

    def _refresh_frontend(self):
        fd = safe_open.open_directory(self.frontend)
        try:
            index = _read_regular(fd, 'index.html')
            if self.frontend_files.get('/') == index:
                return
            files = _capture_build(fd)
            if files.get('/index.html') != index or _read_regular(fd, 'index.html') != index:
                raise ValueError('Frontend build changed during capture')
            references = _BuildReferences()
            references.feed(index.decode('utf-8'))
            brand = {'/assets/favicon.png', '/assets/arvyx-wordmark.png'}
            if references.paths - files.keys() - brand:
                raise ValueError('Incomplete frontend build')
            files['/'] = index
            # Bound retention to one previous generation for already-open pages.
            self.previous_frontend_files = self.frontend_files
            self.frontend_files = files
        finally:
            os.close(fd)

    def frontend_asset(self, path):
        """Promote only complete captures; rebuilding never mutates served bytes.

        A changed index is the build publication marker. Incomplete/removed dist
        keeps the last good capture. Current and previous assets are available;
        a third rebuild retires assets unique to the oldest generation.
        """
        with self.frontend_lock:
            try:
                self._refresh_frontend()
            except (OSError, ValueError):
                pass
            return self.frontend_files.get(path, self.previous_frontend_files.get(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--frontend', type=Path, required=True)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    import getpass
    server = PaperclipServer(args.home, args.frontend, args.port, capability=getpass.getpass('Existing local capability (not stored): '))
    print(server.origin, flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
