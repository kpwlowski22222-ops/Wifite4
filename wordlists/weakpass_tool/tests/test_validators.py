import pytest

from weakpass_integration.exceptions import WeakpassValidationError
from weakpass_integration.validators import validate_hash, validate_prefix


def test_validate_hash_accepts_md5() -> None:
    value = "827ccb0eea8a706c4c34a16891f84e7b"
    assert validate_hash(value) == value


@pytest.mark.parametrize("value", ["", "xyz", "1234", "g" * 32, "a" * 65])
def test_validate_hash_rejects_invalid(value: str) -> None:
    with pytest.raises(WeakpassValidationError):
        validate_hash(value)


def test_validate_prefix_accepts_six_hex_characters() -> None:
    assert validate_prefix("5f4dcc") == "5f4dcc"


@pytest.mark.parametrize("value", ["", "abcd", "zzzzzz", "a" * 65])
def test_validate_prefix_rejects_invalid(value: str) -> None:
    with pytest.raises(WeakpassValidationError):
        validate_prefix(value)
