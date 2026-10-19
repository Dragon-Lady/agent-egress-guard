"""Label-boundary destination classification, with no DNS or network calls."""
from importlib.resources import files
import tomllib


def label_match(host: str, pattern: str) -> bool:
    labels, parts = host.lower().rstrip(".").split("."), pattern.split(".")
    # A leading wildcard covers one or more labels; interior wildcards one.
    if parts[0] == "*":
        if len(labels) < len(parts):
            return False
        labels, parts = labels[-len(parts) + 1:], parts[1:]
    return len(labels) == len(parts) and all(p == "*" or p == h for h, p in zip(labels, parts))


def host_class(host: str) -> str:
    data = tomllib.loads(files("agent_egress_guard").joinpath("data/hosts.toml").read_text())
    return "storage" if any(label_match(host, p) for p in data["storage"]) else "other"
