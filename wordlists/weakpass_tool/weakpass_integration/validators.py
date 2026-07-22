import re
from pathlib import Path

from .constants import (
    BUILTIN_RULESETS,
    SUPPORTED_HASH_TYPES,
    SUPPORTED_OUTPUT_TYPES,
    SUPPORTED_RANGE_FILTERS,
)
from .exceptions import WeakpassValidationError

HEX_HASH_PATTERN = re.compile(r"^[A-Fa-f0-9]{32,64}$")
HEX_PREFIX_PATTERN = re.compile(r"^[A-Fa-f0-9]{6,64}$")


def validate_hash(value: str) -> str:
    normalized = value.strip()
    if not HEX_HASH_PATTERN.fullmatch(normalized):
        raise WeakpassValidationError(
            "Hash musi zawierać od 32 do 64 znaków szesnastkowych."
        )
    return normalized


def validate_prefix(value: str) -> str:
    normalized = value.strip()
    if not HEX_PREFIX_PATTERN.fullmatch(normalized):
        raise WeakpassValidationError(
            "Prefiks musi zawierać od 6 do 64 znaków szesnastkowych."
        )
    return normalized


def validate_hash_type(value: str) -> str:
    normalized = value.lower().strip()
    if normalized not in SUPPORTED_HASH_TYPES:
        raise WeakpassValidationError(
            f"Nieobsługiwany typ hasha: {value}. Dozwolone: "
            f"{', '.join(SUPPORTED_HASH_TYPES)}."
        )
    return normalized


def validate_output_type(value: str) -> str:
    normalized = value.lower().strip()
    if normalized not in SUPPORTED_OUTPUT_TYPES:
        raise WeakpassValidationError(
            f"Nieobsługiwany format: {value}. Dozwolone: "
            f"{', '.join(SUPPORTED_OUTPUT_TYPES)}."
        )
    return normalized


def validate_range_filter(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.lower().strip()
    if normalized not in SUPPORTED_RANGE_FILTERS:
        raise WeakpassValidationError(
            f"Nieobsługiwany filtr: {value}. Dozwolone: "
            f"{', '.join(SUPPORTED_RANGE_FILTERS)}."
        )
    return normalized


def validate_ruleset(value: str) -> str:
    normalized = value.strip()
    if normalized not in BUILTIN_RULESETS:
        raise WeakpassValidationError(
            f"Nieobsługiwany zestaw reguł: {value}. Dozwolone: "
            f"{', '.join(BUILTIN_RULESETS)}."
        )
    return normalized


def validate_existing_file(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise WeakpassValidationError(f"Plik nie istnieje: {resolved}")
    return resolved


def validate_remote_filename(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise WeakpassValidationError("Nazwa pliku nie może być pusta.")
    if "/" in normalized or "\\" in normalized or normalized in {".", ".."}:
        raise WeakpassValidationError("Niedozwolona nazwa zdalnego pliku.")
    return normalized
