from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

EXPECTED_MEMBERS = {"manifest.json", "journal.json"}


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    manifest: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_safe_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return (
        normalized in EXPECTED_MEMBERS
        and not normalized.startswith("/")
        and ".." not in normalized.split("/")
        and ":" not in normalized
    )


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _load_json(member: str, data: bytes, errors: list[str]) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"{member} is not valid UTF-8 JSON: {exc}")
        return None


def verify_bundle(
    path: Path,
    *,
    max_member_bytes: int = 2_000_000,
    max_total_bytes: int = 4_000_000,
) -> VerificationResult:
    errors: list[str] = []
    warnings: list[str] = [
        "local byte consistency only; does not prove external truth",
        "local tamper evidence only; not immutable or WORM storage",
    ]

    if not path.exists():
        return VerificationResult(False, (f"bundle not found: {path}",), tuple(warnings))

    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = {info.filename for info in infos}
            if names != EXPECTED_MEMBERS:
                errors.append(f"expected members {sorted(EXPECTED_MEMBERS)}, got {sorted(names)}")
            for info in infos:
                if not _is_safe_member(info.filename):
                    errors.append(f"unsafe archive member: {info.filename}")
                if info.file_size > max_member_bytes:
                    errors.append(f"member exceeds size budget: {info.filename}")
            total_size = sum(info.file_size for info in infos)
            if total_size > max_total_bytes:
                errors.append("bundle exceeds total size budget")

            manifest_bytes = (
                archive.read("manifest.json") if "manifest.json" in names else b"{}"
            )
            journal_bytes = archive.read("journal.json") if "journal.json" in names else b"{}"
    except zipfile.BadZipFile as exc:
        return VerificationResult(False, (f"invalid zip file: {exc}",), tuple(warnings))

    manifest = _load_json("manifest.json", manifest_bytes, errors)
    journal = _load_json("journal.json", journal_bytes, errors)

    if isinstance(manifest, dict):
        if manifest.get("bundle_type") != "llmwitness-local-evidence":
            errors.append("manifest.bundle_type must be llmwitness-local-evidence")
        if manifest.get("version") != "0.1":
            errors.append("manifest.version must be 0.1")
        expected_digest = manifest.get("journal_digest")
        actual_digest = _sha256_bytes(journal_bytes)
        if expected_digest and expected_digest != actual_digest:
            errors.append("journal_digest does not match journal.json")
        if not expected_digest:
            errors.append("manifest.journal_digest is required")
    else:
        errors.append("manifest.json must contain a JSON object")

    if not isinstance(journal, dict | list):
        errors.append("journal.json must contain a JSON object or array")

    return VerificationResult(
        valid=not errors,
        errors=tuple(errors),
        warnings=tuple(warnings),
        manifest=manifest if isinstance(manifest, dict) else None,
    )

