"""Create or rotate private Home Tunnel relay keys without printing them."""
import argparse
import datetime as dt
import json
import os
import secrets
from pathlib import Path


def atomic_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def rotate(directory, grace_minutes=10):
    if not 0 <= grace_minutes <= 15:
        raise ValueError("Grace period must be between 0 and 15 minutes")
    directory = Path(directory)
    keyfile = directory / "tunnel-keys.json"
    previous = json.loads(keyfile.read_text())["active"] if keyfile.exists() else None
    active = secrets.token_hex(32)
    keys = {"active": active}
    if previous and grace_minutes:
        keys.update(previous=previous, previous_expires_utc=(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=grace_minutes)).isoformat())
    atomic_private(keyfile, json.dumps(keys))
    atomic_private(directory / "tunnel-token.txt", active)
    if not (directory / "metrics-token.txt").exists():
        atomic_private(directory / "metrics-token.txt", secrets.token_hex(32))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True, help="Private local folder outside the web root and Git repo")
    parser.add_argument("--grace-minutes", type=int, default=10)
    args = parser.parse_args()
    rotate(args.directory, args.grace_minutes)
    print("Private key files created; no key values were printed.")
