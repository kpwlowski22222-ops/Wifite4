from weakpass_integration import WeakpassClient


def main() -> None:
    hash_value = "827ccb0eea8a706c4c34a16891f84e7b"
    with WeakpassClient() as client:
        results = client.search_hash(hash_value)
        for item in results:
            print(item)


if __name__ == "__main__":
    main()
