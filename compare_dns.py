"""Compare a saved main-Mac DNS event with the 2018 Mac's observations."""

import argparse
import datetime
import fcntl
import gzip
import json
from pathlib import Path
import runpy
import subprocess

PEER = "yui@macbook-2018.local"
MONITOR = "/run/current-system/sw/bin/wifi-monitor"
LOG_DIR = Path.home() / "Library/Logs/wifi-monitor"
WINDOW = 30


def window(directory, epoch, radius, dns_timings):
    """Project only timings, including across an hourly rotation."""
    start, end = epoch - radius, epoch + radius
    rows = {}

    def add(sample):
        t = sample["epoch"]
        if start <= t <= end:
            rows[t] = {"epoch": t, "timings": dns_timings(sample),
                       "tailscale_configured": sample.get("tailscale_dns_configured")}

    with (directory / ".lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        for path in sorted(directory.glob("samples.jsonl*")):
            with path.open() as file:
                for line in file:
                    old = json.loads(line)
                    t = int(datetime.datetime.fromisoformat(old["time"]).timestamp())
                    if start <= t <= end:
                        # The legacy Intel probe queried example.com via dig's default resolver.
                        ms = old.get("dns_ms")
                        rows[t] = {"epoch": t, "timings": {}, "tailscale_configured": None,
                                   "legacy_dns": {"ok": old.get("dns_status") == "NOERROR",
                                                  "seconds": ms / 1000 if ms is not None else None}}
        for t in range(start, end + 1):
            path = directory / f"sample-{t}.json"
            if path.is_file():
                add(json.loads(path.read_text()))
        for bucket in range(start // 3600, end // 3600 + 1):
            path = directory / f"samples-{bucket * 3600:010d}.jsonl.gz"
            if path.is_file():
                with gzip.open(path, "rt") as file:
                    for line in file:
                        add(json.loads(line))
    return list(rows.values())


def compare(main, peers, *, peer_latest=None):
    from wifi_monitor import SLOW_DNS_SECONDS, slow_dns_paths

    affected = slow_dns_paths(main["timings"])
    nearby = sorted((p for p in peers if abs(p["epoch"] - main["epoch"]) <= WINDOW),
                    key=lambda p: (abs(p["epoch"] - main["epoch"]), p["epoch"]))
    window_complete = peer_latest is not None and peer_latest >= main["epoch"] + WINDOW
    result = {"main": main, "main_slow": affected, "peer_samples": len(nearby),
              "peer_window_complete": window_complete}

    def verdict(label, peer=None):
        return {**result, "scope": label, "peer": peer,
                "offset_s": peer["epoch"] - main["epoch"] if peer else None,
                "peer_slow": slow_dns_paths(peer["timings"]) if peer else []}

    if not affected:
        return verdict("no_main_delay")
    for p in nearby:
        if slow_dns_paths(p["timings"]):
            return verdict("both", p)
    if not window_complete:
        return verdict("unconfirmed", nearby[0] if nearby else None)
    # A missing probe or an unsuccessful lookup cannot establish a fast peer.
    # If relevant failures conflict with nearby fast samples, keep the comparison open.
    for p in nearby:
        if any(p["timings"][k]["status"] != "ok" for k in affected if k in p["timings"]):
            return verdict("unconfirmed", p)
    for p in nearby:
        if all(k in p["timings"] and p["timings"][k]["seconds"] is not None
               and p["timings"][k]["seconds"] < SLOW_DNS_SECONDS for k in affected):
            return verdict("main_only", p)
    return verdict("unconfirmed", nearby[0] if nearby else None)


def peer_window(epoch):
    # Use the Python interpreter pinned by the peer's installed Nix collector.
    command = f'''exec "$(sed -n '1s/^#!//p' {MONITOR})" - --peer-window {int(epoch)}'''
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", PEER, command],
                            input=Path(__file__).read_bytes(), capture_output=True, timeout=45, check=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("epoch", type=int, help="exact epoch of the main-Mac sample")
    parser.add_argument("--peer-window", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.peer_window:
        reader = runpy.run_path(MONITOR)["dns_timings"]
        # Read the committed watermark first. A new sample can arrive during the read.
        latest = json.loads((LOG_DIR / ".state.json").read_text())["epoch"]
        print(json.dumps({"latest": latest, "rows": window(LOG_DIR, args.epoch, WINDOW, reader)}))
        return

    from wifi_monitor import dns_timings
    rows = window(LOG_DIR, args.epoch, 0, dns_timings)
    if not rows:
        parser.exit(1, "Main sample unavailable at the requested epoch.\n")
    result = compare(rows[0], [])
    if result["main_slow"]:
        try:
            peer = peer_window(args.epoch)
            result = compare(rows[0], peer["rows"], peer_latest=peer["latest"])
        except (OSError, subprocess.SubprocessError, ValueError):
            result["peer_read_failed"] = True
    print(json.dumps(result))


if __name__ == "__main__":
    main()
