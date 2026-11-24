import httpx
import pytest

from target import create_app


@pytest.fixture
def target_app(tmp_path):
    return create_app(db_path=str(tmp_path / "target.db"))


@pytest.fixture
def target_client(target_app):
    """HTTP client that calls the target app in-process, no server needed."""
    transport = httpx.WSGITransport(app=target_app)
    with httpx.Client(transport=transport, base_url="http://target") as client:
        yield client


def set_defenses(client: httpx.Client, *names: str) -> None:
    response = client.post("/admin/defenses", json={"active": list(names)})
    assert response.status_code == 200, response.text
