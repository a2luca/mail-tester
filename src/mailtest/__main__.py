import logging

from .app import run
from .config import load_config


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config()
    run(cfg)


if __name__ == "__main__":
    main()
