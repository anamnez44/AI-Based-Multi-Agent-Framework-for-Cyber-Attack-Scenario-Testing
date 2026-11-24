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


def test_failed_run_is_recorded_with_reason(tmp_path):
    conn = storage.connect(str(tmp_path / "h.db"))
    storage.save_run(conn, make_result("closed_loop", blocked=True), "ollama", "big", 1.0)
    storage.save_failed_run(
        conn, "scenario", "sql_injection", "closed_loop", "ollama", "tiny", 0.5,
        "no valid AttackPlan after 3 attempts",
    )

    runs = storage.list_runs(conn)
    failed = next(r for r in runs if r["status"] == "failed")
    assert failed["model"] == "tiny"
    assert failed["attack_type"] == "sql_injection"
    assert "no valid" in failed["error"]
    completed = next(r for r in runs if r["status"] == "completed")
    assert completed["error"] is None


def test_misclassified_run_does_not_count_as_protected(tmp_path):
    conn = storage.connect(str(tmp_path / "h.db"))
    # Blocked, but the Analyst attacked SQLi while the scenario was brute force.
    storage.save_run(
        conn, make_result("closed_loop", blocked=True), "ollama", "tiny", 1.0,
        intended_attack_type="brute_force", seed=7, temperature=0.4,
    )
    run = storage.list_runs(conn)[0]
    assert run["blocked"] is True
    assert run["misclassified"] is True
    assert run["protected_effective"] is False
    assert run["seed"] == 7


def test_correctly_classified_block_is_effective_protection(tmp_path):
    conn = storage.connect(str(tmp_path / "h.db"))
    storage.save_run(
        conn, make_result("closed_loop", blocked=True), "ollama", "big", 1.0,
        intended_attack_type="sql_injection",
    )
    run = storage.list_runs(conn)[0]
    assert run["misclassified"] is False
    assert run["protected_effective"] is True


def test_export_csv_writes_rows(tmp_path):
    conn = storage.connect(str(tmp_path / "h.db"))
    storage.save_run(conn, make_result("closed_loop", blocked=True), "ollama", "m", 1.0, "b1",
                     intended_attack_type="sql_injection")
    storage.save_run(conn, make_result("single_pass", blocked=False), "ollama", "m", 1.0, "b1",
                     intended_attack_type="sql_injection")
    out = tmp_path / "out.csv"
    assert storage.export_csv(conn, str(out), batch="b1") == 2
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("id,created_at,batch")
    assert len(lines) == 3  # header + 2 rows
    assert "protected_effective" in lines[0]
