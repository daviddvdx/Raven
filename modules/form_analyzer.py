"""HTML form inventory and safe classification."""

from __future__ import annotations

from bs4 import BeautifulSoup

from core.models import Finding
from core.result import Endpoint
from core.utils import resolve_url


def extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    forms: list[dict] = []
    for form in soup.find_all("form"):
        action = resolve_url(base_url, form.get("action") or base_url)
        method = (form.get("method") or "GET").upper()
        inputs = []
        hidden = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            item = {"name": name, "type": field.get("type", field.name), "required": field.has_attr("required")}
            inputs.append(item)
            if item["type"] == "hidden":
                hidden.append(name)
        lower = f"{action} {' '.join(item['name'] for item in inputs)}".lower()
        forms.append(
            {
                "action": action,
                "method": method,
                "inputs": inputs,
                "hidden_fields": hidden,
                "has_csrf": any("csrf" in name.lower() or "token" in name.lower() for name in hidden),
                "multipart": "multipart/form-data" in (form.get("enctype") or "").lower(),
                "sensitive": any(token in lower for token in ("login", "password", "otp", "reset", "logout")),
                "upload": "file" in lower or "upload" in lower,
            }
        )
    return forms


def run_form_analyzer(context, html: str | None = None, base_url: str | None = None) -> list[Finding]:
    storage = context["storage"]
    url = base_url or context["target"]
    if html is None:
        result = context["http_client"].safe_request("GET", url)
        html = result.body_text or ""
    forms = extract_forms(html, url)
    findings: list[Finding] = []
    for form in forms:
        storage.append_jsonl("forms.jsonl", form)
        storage.save_endpoint(Endpoint(form["action"], "form", "form-analyzer", method=form["method"], tags=["upload"] if form["upload"] else []).to_dict())
        if form["sensitive"] or form["upload"]:
            findings.append(
                Finding(
                    title="Sensitive form observed",
                    severity="info",
                    endpoint=form["action"],
                    description="Formulaire sensible ou upload identifie. RAVEN ne le soumet pas automatiquement.",
                    proof=f"method={form['method']} fields={len(form['inputs'])} csrf={form['has_csrf']} upload={form['upload']}",
                    score=2,
                    category="form",
                    confidence="medium",
                    reason="login/reset/upload-like form detected",
                    evidence=str(form),
                    next_step="Verifier manuellement le comportement du formulaire dans un cadre autorise.",
                    tags=["form"],
                )
            )
    storage.save_findings(findings)
    return findings
