import pytest

from cyberloop.schemas import DefenseId
from target import ALL_DEFENSES
from target.db import ADMIN_PASSWORD, ADMIN_USER, SECRET_PRODUCT

from .conftest import set_defenses

SQLI_LOGIN = {"username": "' OR '1'='1' --", "password": "wrong"}
SQLI_SEARCH = {"q": "' OR '1'='1' --"}


def test_defense_names_match_the_framework_catalog():
    assert ALL_DEFENSES == {d.value for d in DefenseId}


def test_legitimate_login_succeeds(target_client):
    response = target_client.post("/login", data={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert response.json() == {"authenticated": True, "user": ADMIN_USER}


def test_wrong_password_is_rejected(target_client):
    response = target_client.post("/login", data={"username": ADMIN_USER, "password": "nope"})
    assert response.json() == {"authenticated": False}


def test_login_is_vulnerable_without_defenses(target_client):
    response = target_client.post("/login", data=SQLI_LOGIN)
    body = response.json()
    assert body["authenticated"] is True
    assert body["user"] == ADMIN_USER


def test_search_hides_the_secret_product_normally(target_client):
    assert target_client.get("/products", params={"q": "a"}).json()["products"] == ["Laptop", "Keyboard"]


def test_search_is_vulnerable_without_defenses(target_client):
    assert SECRET_PRODUCT in target_client.get("/products", params=SQLI_SEARCH).json()["products"]


@pytest.mark.parametrize("defense", ["input_validation", "waf_rules"])
def test_login_injection_is_blocked_outright(target_client, defense):
    set_defenses(target_client, defense)
    response = target_client.post("/login", data=SQLI_LOGIN)
    assert response.status_code == 403
    assert response.json() == {"authenticated": False, "blocked": defense}


def test_parameterized_queries_defeat_login_injection(target_client):
    set_defenses(target_client, "parameterized_queries")
    response = target_client.post("/login", data=SQLI_LOGIN)
    assert response.status_code == 200
    assert response.json() == {"authenticated": False}


def test_parameterized_queries_defeat_search_injection(target_client):
    set_defenses(target_client, "parameterized_queries")
    assert SECRET_PRODUCT not in target_client.get("/products", params=SQLI_SEARCH).json()["products"]


def test_defenses_can_be_toggled_and_reset(target_client):
    set_defenses(target_client, "waf_rules", "parameterized_queries")
    assert target_client.get("/admin/defenses").json()["active"] == ["parameterized_queries", "waf_rules"]
    target_client.post("/admin/reset")
    assert target_client.get("/admin/defenses").json()["active"] == []


def test_unknown_defense_is_rejected(target_client):
    response = target_client.post("/admin/defenses", json={"active": ["magic_shield"]})
    assert response.status_code == 400
