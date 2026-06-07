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


def test_noise_level_one_skips_noisy_selected_step(tmp_path):
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    plan.noise_level = 1
    plan.selected_steps = {step.name: False for step in plan.steps}
    plan.selected_steps["content_discovery"] = True
    context = build_context(tmp_path)

    result = manager.run_plan(plan, context)

    assert result["executed"] == []
    assert {"step": "content_discovery", "reason": "noise level 1 disables noisy steps"} in result["skipped"]


def test_run_plan_executes_only_selected_safe_step(tmp_path, monkeypatch):
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    plan.selected_steps = {step.name: False for step in plan.steps}
    plan.selected_steps["scope_validation"] = True
    calls = []

    def fake_run_step(step, context):
        calls.append(step.name)
        return {"status": "ok"}

    monkeypatch.setattr(manager, "run_step", fake_run_step)
    result = manager.run_plan(plan, build_context(tmp_path))

    assert calls == ["scope_validation"]
    assert result["executed"] == [{"step": "scope_validation", "result": {"status": "ok"}}]


def test_load_plan_restores_profile_noise_filters_and_safety(tmp_path):
    manager = WorkflowManager({})
    plan = manager.build_default_plan()
    plan.global_profile = "balanced"
    plan.noise_level = 5
    plan.filters = {"ignore_status": [403, 404], "auto_filter_repeated_sizes": True}
    plan.rate_limit = {"rate": 8, "threads": 4}
    plan.allow_state_changing = True
    plan.selected_steps["xss_reflection_checker"] = True
    context = build_context(tmp_path)
    manager.save_plan(context["storage"].root, plan, "workflow-test")

    loaded = manager.load_plan(context["storage"].root)

    assert loaded.global_profile == "balanced"
    assert loaded.noise_level == 5
    assert loaded.filters["ignore_status"] == [403, 404]
    assert loaded.rate_limit == {"rate": 8, "threads": 4}
    assert loaded.allow_state_changing is True
    assert loaded.selected_steps["xss_reflection_checker"] is True
