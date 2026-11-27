import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_hcrl_artifacts import (
    REQUIRED_ARTIFACTS,
    main,
)


class TestVerifyHcrlArtifacts(unittest.TestCase):
    def _create_artifacts(self, root: Path) -> dict[str, bytes]:
        contents = {
            relative_path: f"fixture:{relative_path}".encode("utf-8")
            for relative_path in REQUIRED_ARTIFACTS
        }
        for relative_path, content in contents.items():
            path = root / Path(relative_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return contents

    def test_hash_listing_reads_all_required_artifacts_without_modifying_them(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            contents = self._create_artifacts(root)
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["--root", str(root)])

            self.assertEqual(result, 0)
            for relative_path, content in contents.items():
                self.assertIn(
                    f"{hashlib.sha256(content).hexdigest()}  {relative_path}",
                    output.getvalue(),
                )
                self.assertEqual(
                    (root / Path(relative_path)).read_bytes(),
                    content,
                )

    def test_trusted_manifest_match_and_mismatch_are_read_only(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            contents = self._create_artifacts(root)
            manifest_path = root / "trusted-hashes.json"
            manifest = {
                relative_path: hashlib.sha256(content).hexdigest()
                for relative_path, content in contents.items()
            }
            manifest_path.write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "--root",
                        str(root),
                        "--manifest",
                        str(manifest_path),
                    ]
                )

            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue().count("OK       "), 6)
            self.assertEqual(
                {
                    relative_path: (root / Path(relative_path)).read_bytes()
                    for relative_path in REQUIRED_ARTIFACTS
                },
                contents,
            )

            changed_path = root / Path(REQUIRED_ARTIFACTS[0])
            changed_path.write_bytes(b"changed fixture")
            before_verification = {
                relative_path: (root / Path(relative_path)).read_bytes()
                for relative_path in REQUIRED_ARTIFACTS
            }
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "--root",
                        str(root),
                        "--manifest",
                        str(manifest_path),
                    ]
                )

            self.assertEqual(result, 1)
            self.assertIn("MISMATCH", output.getvalue())
            self.assertEqual(
                {
                    relative_path: (root / Path(relative_path)).read_bytes()
                    for relative_path in REQUIRED_ARTIFACTS
                },
                before_verification,
            )


if __name__ == "__main__":
    unittest.main()
