"""Measure end-to-end ingestion latency and server CPU/memory against a running API."""
import os
import statistics as st
import sys
import time

import psutil
import requests

from backend.ml.nslkdd import FEATURES, load_nslkdd

base = os.getenv("SECUREWORK_SERVER", "http://127.0.0.1:8000")
n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
tok = requests.post(base + "/api/auth/login", json={"username": os.environ["SECUREWORK_AGENT_USER"],
                    "password": os.environ["SECUREWORK_AGENT_PASSWORD"]}).json()["access_token"]
h = {"Authorization": f"Bearer {tok}"}
requests.post(base + "/api/devices/register", headers=h, json={"device_uid": "perf-device", "name": "perf", "os": "test"})
srv = next((p for p in psutil.process_iter(["cmdline"]) if "uvicorn" in " ".join(p.info["cmdline"] or [])), None)
if srv:
    srv.cpu_percent(None)
df = load_nslkdd("data/nslkdd/KDDTest+.txt").sample(n, random_state=1)
http, proc, pred = [], [], []
t_all = time.perf_counter()
for _, r in df.iterrows():
    f = {k: (r[k].item() if hasattr(r[k], "item") else r[k]) for k in FEATURES}
    t = time.perf_counter()
    j = requests.post(base + "/api/network/events", headers=h, json={"device_uid": "perf-device", "features": f}).json()
    http.append((time.perf_counter() - t) * 1000)
    proc.append(j["processing_ms"]); pred.append(j["predict_ms"])
el = time.perf_counter() - t_all
q = lambda v, p: sorted(v)[int(len(v) * p) - 1]
print(f"events={n} throughput={n/el:.1f}/s")
print(f"model predict ms: mean={st.mean(pred):.2f} p95={q(pred,.95):.2f}")
print(f"server processing ms (predict+DB+alert+log): mean={st.mean(proc):.2f} p95={q(proc,.95):.2f}")
print(f"client round-trip ms: mean={st.mean(http):.2f} p95={q(http,.95):.2f}")
if srv:
    print(f"server CPU%={srv.cpu_percent(None):.1f} RSS MB={srv.memory_info().rss/2**20:.0f}")
