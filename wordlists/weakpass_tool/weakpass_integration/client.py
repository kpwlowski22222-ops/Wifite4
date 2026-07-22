from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import WeakpassConfig
from .exceptions import (
    WeakpassAPIError,
    WeakpassNotFoundError,
    WeakpassRateLimitError,
)
from .models import HashPasswordPair, HashSearchResult
from .validators import (
    validate_existing_file,
    validate_hash,
    validate_hash_type,
    validate_output_type,
    validate_prefix,
    validate_range_filter,
    validate_remote_filename,
    validate_ruleset,
)

HashType = Literal["md5", "ntlm", "sha1", "sha256"]
OutputType = Literal["json", "txt"]
RangeFilter = Literal["hash", "pass"]


class WeakpassClient:
    def __init__(
        self,
        config: WeakpassConfig | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.config = config or WeakpassConfig()
        self.base_url = self.config.normalized_base_url()

        retry_policy = Retry(
            total=self.config.retries,
            connect=self.config.retries,
            read=self.config.retries,
            status=self.config.retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )

        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": self.config.user_agent,
            }
        )

        adapter = HTTPAdapter(max_retries=retry_policy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "WeakpassClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.config.timeout_seconds)
        kwargs.setdefault("verify", self.config.verify_tls)

        try:
            response = self.session.request(
                method=method,
                url=f"{self.base_url}{endpoint}",
                **kwargs,
            )
        except requests.Timeout as exc:
            raise WeakpassAPIError("Przekroczono limit czasu połączenia z API.") from exc
        except requests.RequestException as exc:
            raise WeakpassAPIError(f"Błąd połączenia z Weakpass API: {exc}") from exc

        if response.status_code == 404:
            raise WeakpassNotFoundError("Nie znaleziono danych.")
        if response.status_code == 429:
            raise WeakpassRateLimitError(
                "API ograniczyło częstotliwość zapytań. Spróbuj ponownie później."
            )
        if not response.ok:
            body = response.text[:1000].strip()
            raise WeakpassAPIError(
                f"Weakpass API zwróciło HTTP {response.status_code}: {body}"
            )

        return response

    @staticmethod
    def _parse_json_or_text(response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return response.text

    def search_hash(
        self,
        hash_value: str,
        *,
        typed: bool = False,
    ) -> list[dict[str, Any]] | list[HashSearchResult]:
        normalized_hash = validate_hash(hash_value)
        response = self._request(
            "GET",
            f"/search/{normalized_hash}.json",
            headers={"Accept": "application/json"},
        )
        payload = response.json()
        if not isinstance(payload, list):
            raise WeakpassAPIError("Nieoczekiwany format odpowiedzi endpointu search.")
        return [HashSearchResult.from_api(item) for item in payload] if typed else payload

    def search_hash_text(self, hash_value: str) -> str:
        normalized_hash = validate_hash(hash_value)
        response = self._request(
            "GET",
            f"/search/{normalized_hash}.txt",
            headers={"Accept": "text/plain"},
        )
        return response.text

    def range_lookup(
        self,
        prefix: str,
        *,
        hash_type: HashType = "md5",
        result_filter: RangeFilter | None = None,
        typed: bool = False,
    ) -> list[dict[str, Any]] | list[HashPasswordPair]:
        normalized_prefix = validate_prefix(prefix)
        normalized_type = validate_hash_type(hash_type)
        normalized_filter = validate_range_filter(result_filter)
        params = {"type": normalized_type}
        if normalized_filter is not None:
            params["filter"] = normalized_filter

        response = self._request(
            "GET",
            f"/range/{normalized_prefix}.json",
            params=params,
            headers={"Accept": "application/json"},
        )
        payload = response.json()
        if not isinstance(payload, list):
            raise WeakpassAPIError("Nieoczekiwany format odpowiedzi endpointu range.")
        return [HashPasswordPair.from_api(item) for item in payload] if typed else payload

    def range_lookup_text(
        self,
        prefix: str,
        *,
        hash_type: HashType = "md5",
        result_filter: RangeFilter | None = None,
    ) -> str:
        normalized_prefix = validate_prefix(prefix)
        normalized_type = validate_hash_type(hash_type)
        normalized_filter = validate_range_filter(result_filter)
        params = {"type": normalized_type}
        if normalized_filter is not None:
            params["filter"] = normalized_filter

        response = self._request(
            "GET",
            f"/range/{normalized_prefix}.txt",
            params=params,
            headers={"Accept": "text/plain"},
        )
        return response.text

    def generate(
        self,
        value: str,
        *,
        ruleset: str = "online.rule",
        output_type: OutputType = "json",
    ) -> Any:
        if not value:
            raise ValueError("Wartość wejściowa nie może być pusta.")
        normalized_ruleset = validate_ruleset(ruleset)
        normalized_output = validate_output_type(output_type)
        response = self._request(
            "GET",
            f"/generate/{quote(value, safe='')}",
            params={"set": normalized_ruleset, "type": normalized_output},
        )
        return self._parse_json_or_text(response)

    def generate_post(
        self,
        value: str,
        *,
        ruleset: str = "online.rule",
        output_type: OutputType = "json",
    ) -> Any:
        if not value:
            raise ValueError("Wartość wejściowa nie może być pusta.")
        normalized_ruleset = validate_ruleset(ruleset)
        normalized_output = validate_output_type(output_type)
        response = self._request(
            "POST",
            "/generate",
            params={
                "string": value,
                "set": normalized_ruleset,
                "type": normalized_output,
            },
        )
        return self._parse_json_or_text(response)

    def generate_from_file(
        self,
        value: str,
        rules_file: Path,
        *,
        output_type: OutputType = "txt",
    ) -> Any:
        if not value:
            raise ValueError("Wartość wejściowa nie może być pusta.")
        normalized_output = validate_output_type(output_type)
        resolved_file = validate_existing_file(rules_file)

        with resolved_file.open("rb") as file_handle:
            response = self._request(
                "POST",
                "/generate/file",
                files={"file": (resolved_file.name, file_handle, "text/plain")},
                data={"string": value, "type": normalized_output},
            )
        return self._parse_json_or_text(response)

    def generate_from_file_path(
        self,
        value: str,
        rules_file: Path,
        *,
        output_type: OutputType = "txt",
    ) -> Any:
        if not value:
            raise ValueError("Wartość wejściowa nie może być pusta.")
        normalized_output = validate_output_type(output_type)
        resolved_file = validate_existing_file(rules_file)

        with resolved_file.open("rb") as file_handle:
            response = self._request(
                "POST",
                f"/generate/file/{quote(value, safe='')}",
                files={"file": (resolved_file.name, file_handle, "text/plain")},
                data={"type": normalized_output},
            )
        return self._parse_json_or_text(response)

    def generate_custom(
        self,
        value: str,
        rules: str,
        *,
        output_type: OutputType = "txt",
    ) -> Any:
        if not value:
            raise ValueError("Wartość wejściowa nie może być pusta.")
        if not rules.strip():
            raise ValueError("Reguły nie mogą być puste.")
        normalized_output = validate_output_type(output_type)
        response = self._request(
            "POST",
            f"/generate/custom/{quote(value, safe='')}",
            params={"type": normalized_output},
            data=rules.encode("utf-8"),
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        return self._parse_json_or_text(response)

    def list_wordlists(self) -> list[str]:
        response = self._request(
            "GET",
            "/wordlists",
            headers={"Accept": "application/json"},
        )
        payload = response.json()
        if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
            raise WeakpassAPIError(
                "Nieoczekiwany format odpowiedzi endpointu wordlists."
            )
        return payload

    def download_wordlist(
        self,
        name: str,
        destination: Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        normalized_name = validate_remote_filename(name)
        destination = destination.expanduser().resolve()
        if destination.exists() and not overwrite:
            raise FileExistsError(
                f"Plik już istnieje: {destination}. Użyj overwrite=True."
            )

        response = self._request(
            "GET",
            f"/wordlists/{quote(normalized_name, safe='')}",
            headers={"Accept": "text/plain, application/octet-stream"},
            stream=True,
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".part")

        try:
            with temporary.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        output.write(chunk)
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return destination
