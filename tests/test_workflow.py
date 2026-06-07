from core.storage import Storage
from core.workflow import WorkflowManager


class DummyHTTPClient:
    def close(self):
        pass


def build_context(tmp_path):
    storage = Storage("workflow-test", base_dir=tmp_path)
    return {
        "project": "workflow-test",
        "target": "https://example.com",
        "storage": storage,
        "http_client": DummyHTTPClient(),
        "profile": "quiet",
        "threads": 1,
    }


def test_workflow_dry_run_executes_nothing(tmp_path):
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    plan.dry_run = True
    context = build_context(tmp_path)
    result = manager.run_plan(plan, context)
    assert result["executed"] == []
    assert result["dry_run"] is True


def test_only_selects_one_step():
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    only = {"js_analysis"}
    for step in plan.steps:
        plan.selected_steps[step.name] = step.name in only
    assert plan.selected_steps["js_analysis"] is True
    assert plan.selected_steps["content_discovery"] is False


def test_skip_ignores_step():
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    plan.selected_steps["content_discovery"] = False
    plan.skipped_reasons["content_discovery"] = "skipped by CLI"
    assert plan.selected_steps["content_discovery"] is False


def test_yes_does_not_enable_dangerous_steps():
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    for step in plan.steps:
        if step.requires_tokens or step.can_change_state or (step.can_be_noisy and not step.enabled_by_default):
            plan.selected_steps[step.name] = False
    assert plan.selected_steps["idor_bola_helper"] is False
    assert plan.selected_steps["content_discovery"] is False


def test_workflow_plan_json_is_generated(tmp_path):
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    context = build_context(tmp_path)
    path = manager.save_plan(context["storage"].root, plan, "workflow-test")
    assert path.exists()
    assert "workflow-test" in path.read_text(encoding="utf-8")
