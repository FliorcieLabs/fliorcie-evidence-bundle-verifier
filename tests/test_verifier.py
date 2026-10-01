import hashlib
import json
import zipfile
from pathlib import Path

from fliorcie_evidence_bundle_verifier import verify_bundle


def _write_bundle(path: Path, journal: bytes = b'{"entries": []}') -> None:
    manifest = {
        "bundle_type": "llmwitness-local-evidence",
        "version": "0.1",
        "journal_digest": "sha256:" + hashlib.sha256(journal).hexdigest(),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("journal.json", journal)
        archive.writestr("manifest.json", json.dumps(manifest).encode("utf-8"))


def test_valid_bundle_passes_without_extraction(tmp_path: Path) -> None:
    bundle = tmp_path / "run.llmwitness-evidence.zip"
    _write_bundle(bundle)

    result = verify_bundle(bundle)

    assert result.valid
    assert not result.errors
    assert result.manifest is not None


def test_digest_mismatch_fails(tmp_path: Path) -> None:
    bundle = tmp_path / "run.llmwitness-evidence.zip"
    manifest = {
        "bundle_type": "llmwitness-local-evidence",
        "version": "0.1",
        "journal_digest": "sha256:" + hashlib.sha256(b'{"entries": [1]}').hexdigest(),
    }
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("journal.json", b'{"entries": [2]}')
        archive.writestr("manifest.json", json.dumps(manifest).encode("utf-8"))

    result = verify_bundle(bundle)

    assert not result.valid
    assert any("journal_digest" in error for error in result.errors)


def test_unexpected_member_fails(tmp_path: Path) -> None:
    bundle = tmp_path / "run.llmwitness-evidence.zip"
    _write_bundle(bundle)
    with zipfile.ZipFile(bundle, "a", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("../secret.txt", b"nope")

    result = verify_bundle(bundle)

    assert not result.valid
    assert any("unsafe archive member" in error for error in result.errors)
