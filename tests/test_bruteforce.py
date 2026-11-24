"""Credential-guessing scenario: the login defenses have different coverage.

login_delay only slows guessing, while account_lockout and rate_limiting stop a rapid campaign.
"""

from cyberloop.agents import ExecutorAgent
from cyberloop.orchestrator import LoopDeps, run_scenario
from cyberloop.schemas import AttackPlan, AttackType, DefenseId
from cyberloop.target_control import TargetControl
from target.db import WEAK_PASSWORD, WEAK_USER
from target.defenses import LOCKOUT_THRESHOLD

from .conftest import set_defenses
from .test_orchestrator import NO_COST, EchoEvaluator, PreferenceDefender

GUESS = {"username": WEAK_USER, "password": "wrong"}


def plan():
    return AttackPlan(
        attack_type=AttackType.BRUTE_FORCE,
        mitre_technique_id="T1110.001",
        target_endpoint="/login",
        test_strategy="Guess the password of a weak account.",
        success_criteria=["Valid credentials found"],
        confidence=0.9,
    )


class FixedBruteForceAnalyst:
    def analyze(self, scenario):
        return plan(), NO_COST


# --- target behaviour -------------------------------------------------------

def test_account_lockout_blocks_after_threshold(target_client):
    set_defenses(target_client, "account_lockout")
    for _ in range(LOCKOUT_THRESHOLD):
        assert target_client.post("/login", data=GUESS).status_code == 200
    assert target_client.post("/login", data=GUESS).status_code == 423


def test_rate_limiting_blocks_rapid_requests(target_client):
    set_defenses(target_client, "rate_limiting")
    blocked = [target_client.post("/login", data=GUESS).status_code for _ in range(7)]
    assert 429 in blocked


def test_login_delay_does_not_block(target_client):
    set_defenses(target_client, "login_delay")
    assert target_client.post("/login", data=GUESS).status_code == 200
    ok = target_client.post("/login", data={"username": WEAK_USER, "password": WEAK_PASSWORD})
    assert ok.json() == {"authenticated": True, "user": WEAK_USER}


def test_changing_defenses_clears_the_failure_counter(target_client):
    set_defenses(target_client, "account_lockout")
    for _ in range(LOCKOUT_THRESHOLD):
        target_client.post("/login", data=GUESS)
    set_defenses(target_client, "account_lockout")  # reconfigure -> counters reset
    assert target_client.post("/login", data=GUESS).status_code == 200


# --- executor ---------------------------------------------------------------

def test_executor_guesses_the_weak_password(target_client):
    result = ExecutorAgent(target_client).run(plan(), iteration=1)
    assert result.attack_succeeded
    assert any(WEAK_USER in a.evidence for a in result.attempts if a.succeeded)


def test_login_delay_is_not_enough(target_client):
    set_defenses(target_client, "login_delay")
    result = ExecutorAgent(target_client).run(plan(), iteration=2)
    assert result.attack_succeeded


def test_account_lockout_stops_the_guessing(target_client):
    set_defenses(target_client, "account_lockout")
    result = ExecutorAgent(target_client).run(plan(), iteration=2)
    assert not result.attack_succeeded
    assert any("account_lockout" in a.evidence for a in result.attempts)


# --- full loop --------------------------------------------------------------

def make_deps(target_client, order):
    return LoopDeps(
        analyst=FixedBruteForceAnalyst(),
        executor=ExecutorAgent(target_client),
        evaluator=EchoEvaluator(order),
        defender=PreferenceDefender(order),
        control=TargetControl(target_client),
    )


WEAK_FIRST = [DefenseId.LOGIN_DELAY, DefenseId.ACCOUNT_LOCKOUT, DefenseId.RATE_LIMITING]


def test_closed_loop_escalates_past_the_insufficient_defense(target_client):
    result = run_scenario(make_deps(target_client, WEAK_FIRST), "guess the password", "closed_loop", 3)
    assert result.blocked
    assert result.defenses_applied == ["login_delay", "account_lockout"]
    assert result.iterations == 3


def test_single_pass_stops_at_the_insufficient_defense(target_client):
    result = run_scenario(make_deps(target_client, WEAK_FIRST), "guess the password", "single_pass", 3)
    assert not result.blocked
    assert result.defenses_applied == ["login_delay"]
