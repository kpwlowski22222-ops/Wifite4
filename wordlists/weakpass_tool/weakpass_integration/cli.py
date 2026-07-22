import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Sequence

from .client import WeakpassClient
from .config import WeakpassConfig
from .constants import (
    BUILTIN_RULESETS,
    SUPPORTED_HASH_TYPES,
    SUPPORTED_OUTPUT_TYPES,
    SUPPORTED_RANGE_FILTERS,
)
from .exceptions import WeakpassAPIError


def _serialize(value: Any) -> str:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, list):
        normalized = [asdict(item) if is_dataclass(item) else item for item in value]
        return json.dumps(normalized, ensure_ascii=False, indent=2)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def _write_or_print(value: Any, output: Path | None) -> None:
    text = _serialize(value)
    if output is None:
        print(text)
        return
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    print(f"Zapisano: {output}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="weakpass-tool",
        description="Klient CLI dla Weakpass API.",
    )
    parser.add_argument("--base-url", default="https://weakpass.com/api/v1")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--insecure", action="store_true")

    subparsers = parser.add_subparsers(dest="command", required=True)

    search = subparsers.add_parser("search", help="Wyszukaj pełny hash.")
    search.add_argument("hash")
    search.add_argument("--format", choices=SUPPORTED_OUTPUT_TYPES, default="json")
    search.add_argument("-o", "--output", type=Path)

    range_cmd = subparsers.add_parser("range", help="Pobierz wyniki według prefiksu.")
    range_cmd.add_argument("prefix")
    range_cmd.add_argument("--hash-type", choices=SUPPORTED_HASH_TYPES, default="md5")
    range_cmd.add_argument("--filter", choices=SUPPORTED_RANGE_FILTERS, default=None)
    range_cmd.add_argument("--format", choices=SUPPORTED_OUTPUT_TYPES, default="json")
    range_cmd.add_argument("-o", "--output", type=Path)

    generate = subparsers.add_parser("generate", help="Generator z rulesetem.")
    generate.add_argument("value")
    generate.add_argument("--ruleset", choices=BUILTIN_RULESETS, default="online.rule")
    generate.add_argument("--format", choices=SUPPORTED_OUTPUT_TYPES, default="json")
    generate.add_argument("--post", action="store_true")
    generate.add_argument("-o", "--output", type=Path)

    gen_file = subparsers.add_parser("generate-file", help="Generator z pliku reguł.")
    gen_file.add_argument("value")
    gen_file.add_argument("rules_file", type=Path)
    gen_file.add_argument("--format", choices=SUPPORTED_OUTPUT_TYPES, default="txt")
    gen_file.add_argument("--path-endpoint", action="store_true")
    gen_file.add_argument("-o", "--output", type=Path)

    gen_custom = subparsers.add_parser("generate-custom", help="Reguły jako text/plain.")
    gen_custom.add_argument("value")
    gen_custom.add_argument("rules_file", type=Path)
    gen_custom.add_argument("--format", choices=SUPPORTED_OUTPUT_TYPES, default="txt")
    gen_custom.add_argument("-o", "--output", type=Path)

    subparsers.add_parser("wordlists", help="Lista dostępnych słowników.")

    wordlist = subparsers.add_parser("wordlist", help="Pobierz słownik.")
    wordlist.add_argument("name")
    wordlist.add_argument("-o", "--output", required=True, type=Path)
    wordlist.add_argument("--overwrite", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = WeakpassConfig(
        base_url=args.base_url,
        timeout_seconds=args.timeout,
        retries=args.retries,
        verify_tls=not args.insecure,
    )

    try:
        with WeakpassClient(config=config) as client:
            if args.command == "search":
                result = (
                    client.search_hash_text(args.hash)
                    if args.format == "txt"
                    else client.search_hash(args.hash)
                )
                _write_or_print(result, args.output)

            elif args.command == "range":
                result = (
                    client.range_lookup_text(
                        args.prefix,
                        hash_type=args.hash_type,
                        result_filter=args.filter,
                    )
                    if args.format == "txt"
                    else client.range_lookup(
                        args.prefix,
                        hash_type=args.hash_type,
                        result_filter=args.filter,
                    )
                )
                _write_or_print(result, args.output)

            elif args.command == "generate":
                method = client.generate_post if args.post else client.generate
                result = method(
                    args.value,
                    ruleset=args.ruleset,
                    output_type=args.format,
                )
                _write_or_print(result, args.output)

            elif args.command == "generate-file":
                method = (
                    client.generate_from_file_path
                    if args.path_endpoint
                    else client.generate_from_file
                )
                result = method(
                    args.value,
                    args.rules_file,
                    output_type=args.format,
                )
                _write_or_print(result, args.output)

            elif args.command == "generate-custom":
                rules = args.rules_file.read_text(encoding="utf-8")
                result = client.generate_custom(
                    args.value,
                    rules,
                    output_type=args.format,
                )
                _write_or_print(result, args.output)

            elif args.command == "wordlists":
                _write_or_print(client.list_wordlists(), None)

            elif args.command == "wordlist":
                destination = client.download_wordlist(
                    args.name,
                    args.output,
                    overwrite=args.overwrite,
                )
                print(destination)

    except (WeakpassAPIError, OSError, ValueError) as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
