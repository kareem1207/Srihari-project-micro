import os
import time

import pytest
from fastapi.testclient import TestClient

os.environ["SECUREWORK_JWT_SECRET"] = "x" * 40
os.environ["SECUREWORK_LOG_FILE"] = "/tmp/sw_test_events.jsonl"
os.environ["SECUREWORK_ES_URL"] = ""

from backend import db as dbmod  # noqa: E402
from backend.api import app  # noqa: E402
from backend.ml.nslkdd import FEATURES, load_nslkdd  # noqa: E402
from backend.models import User  # noqa: E402
from backend.security import hash_password  # noqa: E402

TEST_CSV = "data/nslkdd/KDDTest+.txt"
MODEL = "models/nslkdd_ids.joblib"
needs_model = pytest.mark.skipif(not (os.path.exists(MODEL) and os.path.exists(TEST_CSV)), reason="model/dataset missing")


@pytest.fixture(scope="module")
def client():
    dbmod.init_engine("sqlite:///:memory:")
    with dbmod.session()() as s:
        for n, r in (("adm", "admin"), ("ana", "analyst"), ("agt", "agent")):
            s.add(User(username=n, password_hash=hash_password("Passw0rd!long"), role=r))
        s.commit()
    return TestClient(app)


def tok(c, u):
    r = c.post("/api/auth/login", json={"username": u, "password": "Passw0rd!long"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_auth_required_and_bad_login(client):
    assert client.get("/api/devices").status_code == 401
    assert client.post("/api/auth/login", json={"username": "adm", "password": "wrong"}).status_code == 401


def test_rbac(client):
    ana, adm = tok(client, "ana"), tok(client, "adm")
    assert client.post("/api/users", headers=ana, json={"username": "zed", "password": "Passw0rd!long"}).status_code == 403
    assert client.post("/api/users", headers=adm, json={"username": "zed", "password": "short"}).status_code == 422
    assert client.post("/api/users", headers=adm, json={"username": "zed", "password": "Passw0rd!long"}).status_code == 201
    assert client.get("/api/audit", headers=ana).status_code == 403


def test_device_and_validation(client):
    agt = tok(client, "agt")
    assert client.post("/api/devices/register", headers=agt, json={"device_uid": "bad uid!", "name": "x"}).status_code == 422
    r = client.post("/api/devices/register", headers=agt, json={"device_uid": "PC-001", "name": "Laptop", "os": "Windows 11"})
    assert r.status_code == 200
    devs = client.get("/api/devices", headers=tok(client, "ana")).json()
    assert devs[0]["name"] == "Laptop" and devs[0]["status"] == "online"


def test_application_allowlist_flow(client):
    agt, adm, ana = tok(client, "agt"), tok(client, "adm"), tok(client, "ana")
    client.post("/api/applications/allowlist", headers=adm, json={"name": "winword.exe"})
    body = {"device_uid": "PC-001", "applications": [
        {"name": "winword.exe", "exe_path": "C:\\Program Files\\Office\\winword.exe"},
        {"name": "evil.exe", "exe_path": "C:\\Users\\x\\AppData\\evil.exe"}]}
    assert client.post("/api/applications/report", headers=agt, json=body).json()["unauthorized_events"] == 1
    # duplicate suppressed within window
    assert client.post("/api/applications/report", headers=agt, json=body).json()["unauthorized_events"] == 0
    ev = client.get("/api/application-events", headers=ana).json()
    assert len(ev) == 1 and ev[0]["application"] == "evil.exe" and ev[0]["severity"] == "high"
    logs = client.get("/api/logs?source=application", headers=ana).json()
    assert logs["total"] == 1


def test_unscored_network_event_has_no_alert(client):
    agt = tok(client, "agt")
    r = client.post("/api/network/events", headers=agt, json={"device_uid": "PC-001", "src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "protocol": "tcp", "source": "connection-scan"})
    assert r.status_code == 201 and r.json()["classification"] == "unscored" and r.json()["alert_id"] is None


@needs_model
def test_ml_detection_alert_and_dedup(client):
    agt, ana = tok(client, "agt"), tok(client, "ana")
    df = load_nslkdd(TEST_CSV)
    attack = df[(df.label == "neptune")].iloc[0]
    normal = df[df.label == "normal"].iloc[0]

    def feats(row, label=True):
        f = {k: (row[k].item() if hasattr(row[k], "item") else row[k]) for k in FEATURES}
        if label:
            f["label"] = row["label"]
        return f
    r = client.post("/api/network/events", headers=agt, json={"device_uid": "PC-001", "source": "dataset-replay", "features": feats(attack)}).json()
    assert r["classification"] == "suspicious" and r["alert_id"]
    r2 = client.post("/api/network/events", headers=agt, json={"device_uid": "PC-001", "source": "dataset-replay", "features": feats(attack)}).json()
    assert r2["alert_id"] == r["alert_id"]  # deduplicated
    alert = [a for a in client.get("/api/alerts", headers=ana).json() if a["id"] == r["alert_id"]][0]
    assert alert["occurrences"] == 2 and alert["attack_category"] == "DoS" and alert["severity"] in ("high", "medium")
    n = client.post("/api/network/events", headers=agt, json={"device_uid": "PC-001", "features": feats(normal, False)}).json()
    assert n["classification"] == "normal" and n["alert_id"] is None
    bad = client.post("/api/network/events", headers=agt, json={"device_uid": "PC-001", "features": {"duration": 1}})
    assert bad.status_code == 422


def test_dashboard_and_health(client):
    s = client.get("/api/dashboard/stats", headers=tok(client, "ana")).json()
    assert s["devices_total"] == 1 and s["security_events"] >= 2
    assert client.get("/api/health").json()["database"] == "up"
    assert client.get("/").status_code == 200


def test_severity_rules():
    from backend.alerts import app_severity, intrusion_severity
    assert intrusion_severity("U2R", 0.9) == "critical"
    assert intrusion_severity("DoS", 0.5) == "medium"
    assert app_severity("C:\\Program Files\\a.exe") == "medium"
    assert app_severity("C:\\Users\\a.exe") == "high"
