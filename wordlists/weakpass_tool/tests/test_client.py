from pathlib import Path

import responses

from weakpass_integration.client import WeakpassClient
from weakpass_integration.config import WeakpassConfig


@responses.activate
def test_search_hash() -> None:
    hash_value = "827ccb0eea8a706c4c34a16891f84e7b"
    responses.get(
        f"https://weakpass.com/api/v1/search/{hash_value}.json",
        json=[{"type": "md5", "hash": hash_value, "pass": "12345"}],
        status=200,
    )
    client = WeakpassClient()
    result = client.search_hash(hash_value)
    assert result[0]["pass"] == "12345"


@responses.activate
def test_range_lookup() -> None:
    responses.get(
        "https://weakpass.com/api/v1/range/5f4dcc.json",
        json=[
            {
                "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
                "pass": "password",
            }
        ],
        status=200,
    )
    client = WeakpassClient()
    result = client.range_lookup("5f4dcc")
    assert result[0]["pass"] == "password"


@responses.activate
def test_download_wordlist(tmp_path: Path) -> None:
    responses.get(
        "https://weakpass.com/api/v1/wordlists/example.txt",
        body=b"password\n123456\n",
        status=200,
        content_type="text/plain",
    )
    destination = tmp_path / "example.txt"
    client = WeakpassClient(WeakpassConfig(retries=0))
    returned = client.download_wordlist("example.txt", destination)
    assert returned == destination.resolve()
    assert destination.read_text() == "password\n123456\n"
