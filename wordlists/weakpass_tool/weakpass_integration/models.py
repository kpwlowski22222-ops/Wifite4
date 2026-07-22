from dataclasses import dataclass
from typing import Any, Literal

HashType = Literal["md5", "ntlm", "sha1", "sha256"]


@dataclass(frozen=True, slots=True)
class HashPasswordPair:
    hash: str
    password: str

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "HashPasswordPair":
        return cls(
            hash=str(payload.get("hash", "")),
            password=str(payload.get("pass", "")),
        )


@dataclass(frozen=True, slots=True)
class HashSearchResult:
    type: HashType
    hash: str
    password: str

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "HashSearchResult":
        return cls(
            type=str(payload.get("type", "")).lower(),  # type: ignore[arg-type]
            hash=str(payload.get("hash", "")),
            password=str(payload.get("pass", "")),
        )
