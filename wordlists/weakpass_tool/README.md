# Weakpass Tool

Klient CLI i biblioteka Python do integracji z publicznym API Weakpass.

## Funkcje

- wyszukiwanie pełnego hasha,
- pobieranie zakresu po prefiksie,
- generowanie wariantów słowa z reguł Hashcat,
- generowanie z własnego pliku reguł,
- generowanie z reguł przekazanych jako tekst,
- listowanie i pobieranie wordlist,
- walidacja danych wejściowych,
- retry/backoff i obsługa błędów HTTP,
- zapis wyników do pliku.

> Używaj wyłącznie wobec danych i systemów, do których masz uprawnienia.

## Instalacja

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

## CLI

```bash
weakpass-tool --help
```

### Wyszukiwanie hasha

```bash
weakpass-tool search 827ccb0eea8a706c4c34a16891f84e7b
```

### Pobranie zakresu

```bash
weakpass-tool range 5f4dcc --hash-type md5 --format json
```

### Generator

```bash
weakpass-tool generate EvilCorp --ruleset online.rule --format txt
```

### Własny plik reguł

```bash
weakpass-tool generate-file EvilCorp ./custom.rule --format txt
```

### Reguły jako zwykły tekst

```bash
weakpass-tool generate-custom EvilCorp ./custom.rule --format txt
```

### Lista słowników

```bash
weakpass-tool wordlists
```

### Pobranie słownika

```bash
weakpass-tool wordlist rockyou.txt --output ./downloads/rockyou.txt
```

## Użycie jako biblioteka

```python
from weakpass_integration import WeakpassClient

client = WeakpassClient()
results = client.search_hash("827ccb0eea8a706c4c34a16891f84e7b")
print(results)
```

## Testy

```bash
python -m pip install -e ".[dev]"
pytest -q
```
