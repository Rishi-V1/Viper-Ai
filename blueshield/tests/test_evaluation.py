from app.services import evaluation


def test_run_evaluation_on_bundled_scenarios_scores_perfectly():
    """The bundled generator data is exactly what labels.json describes, so
    a correct correlation engine should pass every scenario.
    """
    result = evaluation.run_evaluation()

    assert result["confusion_matrix"]["false_positive"] == 0
    assert result["confusion_matrix"]["false_negative"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["false_positive_rate"] == 0.0

    for scenario in result["scenario_results"]:
        assert scenario["result"] in ("true_positive", "true_negative", "pass")


def test_run_evaluation_reports_processing_latency():
    result = evaluation.run_evaluation()
    assert isinstance(result["processing_latency_ms"], int)
    assert result["processing_latency_ms"] >= 0


def test_llm_evaluation_summary_with_no_analyses(tmp_path):
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE model_analyses (model_tag TEXT, validation_status TEXT, latency_ms INTEGER)")
    summary = evaluation.llm_evaluation_summary(conn)
    assert summary["total_analyses"] == 0


def test_llm_evaluation_summary_aggregates_per_model():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE model_analyses (model_tag TEXT, validation_status TEXT, latency_ms INTEGER)")
    conn.executemany(
        "INSERT INTO model_analyses VALUES (?, ?, ?)",
        [
            ("qwen2.5-coder:latest", "valid", 500),
            ("qwen2.5-coder:latest", "invalid_json", 700),
            ("deepseek-r1:latest", "valid", 1200),
        ],
    )
    summary = evaluation.llm_evaluation_summary(conn)
    assert summary["total_analyses"] == 3
    qwen = next(m for m in summary["per_model"] if m["model_tag"] == "qwen2.5-coder:latest")
    assert qwen["total_analyses"] == 2
    assert qwen["validity_rate"] == 0.5
