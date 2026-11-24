from fastapi.testclient import TestClient

from api import create_api
from cyberloop import storage

from .test_storage import make_result


def client_with_history(tmp_path):
    db_path = str(tmp_path / "h.db")
    conn = storage.connect(db_path)
    storage.save_run(conn, make_result("single_pass", blocked=False), "ollama", "qwen", 1.0, "b1")
    storage.save_run(conn, make_result("closed_loop", blocked=True), "ollama", "qwen", 2.0, "b1")
    conn.close()
    return TestClient(create_api(db_path))


def test_health(tmp_path):
    assert client_with_history(tmp_path).get("/health").json() == {"status": "ok"}


def test_list_runs(tmp_path):
    runs = client_with_history(tmp_path).get("/runs").json()
    assert len(runs) == 2
    assert {r["mode"] for r in runs} == {"single_pass", "closed_loop"}


def test_run_detail_and_404(tmp_path):
    client = client_with_history(tmp_path)
    runs = client.get("/runs").json()
    detail = client.get(f"/runs/{runs[0]['id']}").json()
    assert "records" in detail
    assert client.get("/runs/9999").status_code == 404


def test_stats_group_by_mode(tmp_path):
    stats = client_with_history(tmp_path).get("/stats").json()
    by_mode = {s["mode"]: s for s in stats}
    assert by_mode["closed_loop"]["protected_rate"] == 1.0
    assert by_mode["single_pass"]["protected_rate"] == 0.0
