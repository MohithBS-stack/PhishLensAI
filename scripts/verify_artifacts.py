"""Model Artifact Integrity and Checksum Verification Script.

Validates that model artifacts exist and match expected SHA-256 checksums before runtime deployment.
"""
import hashlib
import sys
from pathlib import Path

EXPECTED_ARTIFACTS = {
    "sms_classifier.joblib": {
        "sha256": "dff70e37c5dfd6ebd5145ddca5e8d086861cc83a63ed6ded3395b0b8b9e455c4",
        "min_size_bytes": 200000,
    },
    "url_classifier.joblib": {
        "sha256": "f98952073aa236c15bcf1e5d3df8e2ca7c25af87c678b54b6abb0d2c7d5a2946",
        "min_size_bytes": 500000,
    },
    "metadata.json": {
        "sha256": "0fed19cc7c78479c315fafc10cb81c5eb8b70150a07d28344966b1ec1ff713a1",
        "min_size_bytes": 500,
    },
}


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def verify_artifacts(models_dir: Path) -> bool:
    """Verifies all required model artifacts in target directory."""
    print(f"[*] Checking model artifacts in: {models_dir.resolve()}")
    all_valid = True

    for filename, specs in EXPECTED_ARTIFACTS.items():
        file_path = models_dir / filename
        if not file_path.exists():
            print(f"[!] MISSING: {filename} does not exist at {file_path}")
            all_valid = False
            continue

        size = file_path.stat().st_size
        if size < specs["min_size_bytes"]:
            print(f"[!] INVALID SIZE: {filename} size ({size} bytes) below minimum expected ({specs['min_size_bytes']} bytes)")
            all_valid = False
            continue

        computed_hash = compute_sha256(file_path)
        expected_hash = specs["sha256"].lower()

        if computed_hash == expected_hash:
            print(f"[OK] VERIFIED: {filename} ({size} bytes) matches expected SHA-256: {computed_hash[:16]}...")
        else:
            print(f"[!] HASH MISMATCH: {filename}")
            print(f"    Expected: {expected_hash}")
            print(f"    Computed: {computed_hash}")
            all_valid = False

    return all_valid


if __name__ == "__main__":
    # Look for models/saved/ relative to repo root or CWD
    candidates = [
        Path("models/saved"),
        Path("../models/saved"),
        Path(__file__).resolve().parents[1] / "models" / "saved",
    ]
    target_dir = None
    for cand in candidates:
        if cand.exists():
            target_dir = cand
            break

    if not target_dir:
        print("[!] Error: Could not locate 'models/saved' directory.")
        sys.exit(1)

    success = verify_artifacts(target_dir)
    if success:
        print("\n[OK] All model artifacts verified successfully. Safe for deployment.")
        sys.exit(0)
    else:
        print("\n[!] Artifact verification failed. Do not deploy.")
        sys.exit(1)
