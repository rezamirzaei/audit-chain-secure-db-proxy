"""Convenience entrypoint for local development."""


def main() -> None:
    print("This repo contains two services:")
    print("  - database_server/")
    print("  - proxy_clone/")
    print("")
    print("Use one of:")
    print("  ./scripts/run.sh docker")
    print("  ./scripts/run.sh local")
    print("  docker-compose up --build")


if __name__ == "__main__":
    main()
