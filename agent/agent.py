"""SecureWork AI monitoring agent (Windows target; also runs on Linux/macOS for testing).

Collects: running processes (psutil) -> application events vs the server allowlist,
          established TCP connections (psutil) -> 'unscored' network events (connection-scan),
          optional dataset replay -> ML-scored events labelled 'dataset-replay' (NOT live traffic).
Authenticates with an 'agent' role account (SECUREWORK_AGENT_USER / SECUREWORK_AGENT_PASSWORD).
No admin rights are required for this process/connection listing (some system processes
may hide their paths without elevation).
"""
import argparse
import os
import platform
import socket
import sys
import time
import uuid

import psutil
import requests


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        r = requests.post(f"{self.base}/api/auth/login", json={
            "username": os.environ["SECUREWORK_AGENT_USER"],
            "password": os.environ["SECUREWORK_AGENT_PASSWORD"]}, timeout=10)
        r.raise_for_status()
        self.h = {"Authorization": f"Bearer {r.json()['access_token']}"}

    def post(self, path, body):
        r = requests.post(self.base + path, json=body, headers=self.h, timeout=30)
        r.raise_for_status()
        return r.json()


def device_uid() -> str:
    return os.getenv("SECUREWORK_DEVICE_UID") or f"{socket.gethostname()}-{uuid.getnode():012x}"


def running_apps() -> list[dict]:
    seen = {}
    for p in psutil.process_iter(["name", "exe"]):
        n = p.info.get("name")
        if n and n.lower() not in seen:
            seen[n.lower()] = {"name": n, "exe_path": p.info.get("exe") or ""}
    return list(seen.values())


def connections() -> list[dict]:
    out = []
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.status == "ESTABLISHED" and c.raddr:
                out.append({"src_ip": c.laddr.ip, "dst_ip": c.raddr.ip, "protocol": "tcp"})
    except (psutil.AccessDenied, OSError):
        pass
    return out


def replay(c: Client, uid: str, csv: str, n: int):
    from backend.ml.nslkdd import FEATURES, load_nslkdd
    df = load_nslkdd(csv).sample(n, random_state=7)
    for _, row in df.iterrows():
        feats = {f: (row[f].item() if hasattr(row[f], "item") else row[f]) for f in FEATURES}
        feats["label"] = row["label"]
        c.post("/api/network/events", {"device_uid": uid, "source": "dataset-replay", "features": feats})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default=os.getenv("SECUREWORK_SERVER", "http://127.0.0.1:8000"))
    ap.add_argument("--interval", type=int, default=60)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--replay", type=int, default=0, help="replay N NSL-KDD test records (demo only)")
    ap.add_argument("--replay-csv", default="data/nslkdd/KDDTest+.txt")
    a = ap.parse_args()
    c, uid = Client(a.server), device_uid()
    c.post("/api/devices/register", {"device_uid": uid, "name": socket.gethostname(),
                                     "os": f"{platform.system()} {platform.release()}"})
    if a.replay:
        replay(c, uid, a.replay_csv, a.replay)
    while True:
        print("apps:", c.post("/api/applications/report", {"device_uid": uid, "applications": running_apps()}))
        for conn in connections()[:200]:
            c.post("/api/network/events", {"device_uid": uid, "source": "connection-scan", **conn})
        c.post(f"/api/devices/{uid}/heartbeat", {})
        if a.once:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
