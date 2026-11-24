from cyberloop import storage
from cyberloop.orchestrator import IterationRecord, RunResult
from cyberloop.schemas import (
    AttackPlan,
    AttackType,
    AttemptResult,
    ExecutionResult,
)


def make_result(mode: str, blocked: bool) -> RunResult:
    plan = AttackPlan(
        attack_type=AttackType.SQL_INJECTION,
        mitre_technique_id="T1190",
        target_endpoint="/login",
        test_strategy="probe",
        success_criteria=["bypass"],
        confidence=0.9,
    )
    execution = ExecutionResult(
        iteration=1,
        attack_type=AttackType.SQL_INJECTION,
        target_endpoint="/login",
        attempts=[AttemptResult(payload="p", succeeded=not blocked, evidence="e")],
        duration_s=0.1,
    )
    return RunResult(
        mode=mode,
        scenario="scenario text",
        plan=plan,
        blocked=blocked,
        stop_reason="done",
        iterations=1,
        defenses_applied=["parameterized_queries"] if blocked else [],
        initial_success_rate=1.0,
        final_success_rate=0.0 if blocked else 1.0,
        records=[IterationRecord(iteration=1, execution=execution)],
    )


def test_save_and_list_roundtrip(tmp_path):
    conn = storage.connect(str(tmp_path / "h.db"))
    storage.save_run(conn, make_result("single_pass", blocked=False), "ollama", "m", 1.0)
    storage.save_run(conn, make_result("closed_loop", blocked=True), "ollama", "m", 2.0, batch="b1")

    runs = storage.list_runs(conn)
    assert len(runs) == 2
    latest = runs[0]
    assert latest["mode"] == "closed_loop"
    assert latest["blocked"] is True
    assert latest["defenses_applied"] == ["parameterized_queries"]
    assert latest["batch"] == "b1"


def test_get_run_includes_records(tmp_path):
    conn = storage.connect(str(tmp_path / "h.db"))
    run_id = storage.save_run(conn, make_result("closed_loop", blocked=True), "ollama", "m", 1.0)
    detail = storage.get_run(conn, run_id)
    assert detail["records"][0]["execution"]["attack_type"] == "sql_injection"


def test_get_missing_run_returns_none(tmp_path):
    conn = storage.connect(str(tmp_path / "h.db"))
    assert storage.get_run(conn, 999) is None
