class WeakpassAPIError(RuntimeError):
    """Bazowy wyjątek klienta Weakpass."""


class WeakpassValidationError(WeakpassAPIError, ValueError):
    """Nieprawidłowe dane wejściowe."""


class WeakpassNotFoundError(WeakpassAPIError):
    """API nie zwróciło danych dla wskazanego zasobu."""


class WeakpassRateLimitError(WeakpassAPIError):
    """API ograniczyło częstotliwość zapytań."""
