from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WeakpassConfig:
    base_url: str = "https://weakpass.com/api/v1"
    timeout_seconds: float = 30.0
    retries: int = 3
    backoff_factor: float = 1.0
    user_agent: str = "WeakpassTool/1.0"
    verify_tls: bool = True

    def normalized_base_url(self) -> str:
        return self.base_url.rstrip("/")
