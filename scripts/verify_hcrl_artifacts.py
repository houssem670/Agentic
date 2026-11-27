"""Calculate and optionally verify SHA-256 hashes for HCRL benchmark artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Sequence


REQUIRED_ARTIFACTS = (
    "datasets/hcrl/normal_run_data.txt",
    "datasets/hcrl/gear_dataset.csv",
    "datasets/hcrl/DoS_dataset.csv",
    "datasets/hcrl/Fuzzy_dataset.csv",
    "datasets/hcrl/RPM_dataset.csv",
    "models/hcrl_ml_detector.joblib",
)
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def calculate_artifact_hashes(root: Path) -> dict[str, str]:
    missing = [
        relative_path
        for relative_path in REQUIRED_ARTIFACTS
        if not (root / Path(relative_path)).is_file()
    ]
    if missing:
        raise FileNotFoundError(
            "Required HCRL artifacts are missing: " + ", ".join(missing)
        )

    return {
        relative_path: sha256_file(root / Path(relative_path))
        for relative_path in REQUIRED_ARTIFACTS
    }


def load_expected_hashes(manifest_path: Path) -> dict[str, str]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON manifest: {manifest_path}") from exc

    if not isinstance(manifest, dict):
        raise ValueError("The SHA-256 manifest must be a JSON object.")

    required = set(REQUIRED_ARTIFACTS)
    provided = set(manifest)
    missing = sorted(required - provided)
    unexpected = sorted(provided - required)
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing entries: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected entries: " + ", ".join(unexpected))
        raise ValueError("Invalid manifest coverage (" + "; ".join(details) + ").")

    expected: dict[str, str] = {}
    for relative_path, value in manifest.items():
        if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
            raise ValueError(
                f"Invalid SHA-256 digest for manifest entry {relative_path!r}."
            )
        expected[relative_path] = value.lower()
    return expected


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root containing the dataset and model paths",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help=(
            "optional trusted JSON mapping of the six relative artifact paths "
            "to expected SHA-256 digests"
        ),
    )
    args = parser.parse_args(argv)

    try:
        expected = (
            load_expected_hashes(args.manifest)
            if args.manifest is not None
            else None
        )
        actual = calculate_artifact_hashes(args.root)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if expected is None:
        for relative_path, digest in actual.items():
            print(f"{digest}  {relative_path}")
        print(
            "No trusted manifest supplied; hashes are fingerprints, "
            "not authenticity verification."
        )
        return 0

    matched = True
    for relative_path, digest in actual.items():
        if digest == expected[relative_path]:
            print(f"OK       {relative_path}")
        else:
            matched = False
            print(
                f"MISMATCH {relative_path}: expected {expected[relative_path]}, "
                f"got {digest}"
            )
    return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
