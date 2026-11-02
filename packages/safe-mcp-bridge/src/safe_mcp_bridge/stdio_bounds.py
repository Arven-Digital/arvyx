"""Bounded UTF-8 newline intake; oversized frames are drained, never retained."""
MAX_STDIO_BYTES = 1024 * 1024


def bounded_lines(stream):
    stream = getattr(stream, 'buffer', stream)
    while True:
        part = stream.readline(MAX_STDIO_BYTES + 1)
        if not part:
            return
        binary = isinstance(part, bytes)
        newline = b'\n' if binary else '\n'
        size = len(part) if binary else len(part.encode('utf-8'))
        if size > MAX_STDIO_BYTES:
            while part and not part.endswith(newline):
                part = stream.readline(MAX_STDIO_BYTES + 1)
            yield None
            continue
        try:
            yield part.decode('utf-8') if binary else part
        except UnicodeDecodeError:
            yield None
