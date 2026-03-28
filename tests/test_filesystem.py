import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zacaim.filesystem import resolve_app_dir


class FilesystemTest(unittest.TestCase):
    def test_resolve_app_dir_prefers_cwd_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            with patch.dict("os.environ", {}, clear=True):
                app_dir = resolve_app_dir(temp_path)
            self.assertEqual(app_dir, temp_path / ".zacaim_v2")
            self.assertTrue(app_dir.exists())


if __name__ == "__main__":
    unittest.main()
