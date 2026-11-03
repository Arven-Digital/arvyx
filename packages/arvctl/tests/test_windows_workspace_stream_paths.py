"""Windows workspace selections reject NTFS stream syntax before exclusion checks."""
from unittest.mock import patch

import pytest

from arvyx_control import external_workspace


@pytest.mark.parametrize('value', ['secret.key::$DATA', 'notes.txt:private', 'folder:stream/file.txt'])
def test_windows_workspace_rejects_stream_components(value):
    with patch.object(external_workspace.os, 'name', 'nt'):
        with pytest.raises(external_workspace.WorkspaceError, match='invalid relative path'):
            external_workspace._path(value, 4096)


def test_posix_workspace_preserves_colon_filename():
    with patch.object(external_workspace.os, 'name', 'posix'):
        assert external_workspace._path('notes:local.txt', 4096) == ('notes:local.txt',)
