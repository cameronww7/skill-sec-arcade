#!/usr/bin/env python3
"""A small, harmless helper used only by the benign fixture skill."""

import json
import os


def read_config(path):
    """Reads a JSON config file, returning an empty dict on failure."""
    try:
        with open(path, "r", encoding="utf-8") as config_file:
            return json.load(config_file)
    except (OSError, ValueError):
        return {}


def main():
    config = read_config(os.path.join(os.path.dirname(__file__), "config.json"))
    print(json.dumps(config))


if __name__ == "__main__":
    main()
