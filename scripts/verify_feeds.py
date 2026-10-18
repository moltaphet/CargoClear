"""Verifies that every pinned mock feed answers HTTP 200 on all three operator
hosts and that the bytes are identical to the committed file.

    python scripts/verify_feeds.py [<commit-sha>]    # default: HEAD of the feed commit in git

Exit status 0 only when every (host, feed) pair is 200 with byte parity.
"""

import hashlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OWNER, REPO = "moltaphet", "CargoClear"
FEEDS = ("a", "b", "c")
NAME = "LC-1.json"


def feed_urls(sha: str, folder: str, name: str = NAME) -> dict:
    path = f"deployments/mock_feeds/{folder}/{name}"
    return {
        "raw.githubusercontent.com": f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{sha}/{path}",
        "cdn.jsdelivr.net": f"https://cdn.jsdelivr.net/gh/{OWNER}/{REPO}@{sha}/{path}",
        "raw.githack.com": f"https://raw.githack.com/{OWNER}/{REPO}/{sha}/{path}",
    }


def fetch(url: str, attempts: int = 6, wait: float = 10.0):
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cargoclear-verify/1"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            last = (exc.code, b"")
            if exc.code != 404:
                return last
        except Exception as exc:  # noqa: BLE001
            last = (0, str(exc).encode())
        time.sleep(wait * (i + 1))
    return last


def main() -> int:
    sha = sys.argv[1] if len(sys.argv) > 1 else subprocess.check_output(
        ["git", "log", "-1", "--format=%H", "--", "deployments/mock_feeds"], cwd=ROOT, text=True
    ).strip()
    print(f"commit {sha}")
    failures = 0
    for folder in FEEDS:
        local = (ROOT / "deployments" / "mock_feeds" / folder / NAME).read_bytes()
        digest = hashlib.sha256(local).hexdigest()
        for host, url in feed_urls(sha, folder).items():
            status, body = fetch(url)
            parity = hashlib.sha256(body).hexdigest() == digest
            good = status == 200 and parity
            failures += 0 if good else 1
            print(f"{'OK  ' if good else 'FAIL'} {status} parity={parity} {host:26s} feed={folder} sha256={digest[:16]}")
    print("ALL FEEDS: HTTP 200 with byte parity on all 3 hosts" if not failures else f"{failures} FAILURES")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
