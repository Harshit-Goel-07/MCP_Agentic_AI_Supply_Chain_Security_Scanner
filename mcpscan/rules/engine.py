"""Load the declarative rule catalog and enrich findings with canonical metadata."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml
from pydantic import BaseModel

from mcpscan.config import Severity
from mcpscan.models import Finding


class Rule(BaseModel):
    id: str
    title: str
    owasp_mcp_id: str
    category: str
    default_severity: Severity
    remediation: str = ""


class RuleCatalog(BaseModel):
    catalog_version: str
    rules: list[Rule]

    def by_id(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def enrich(self, finding: Finding) -> Finding:
        """Fill in canonical title / OWASP id from the catalog when a finding omits them."""

        rule = self.by_id(finding.rule_id)
        if rule is None:
            return finding
        if not finding.title:
            finding.title = rule.title
        if finding.owasp_mcp_id is None:
            finding.owasp_mcp_id = rule.owasp_mcp_id
        finding.evidence.setdefault("category", rule.category)
        finding.evidence.setdefault("remediation", rule.remediation.strip())
        return finding


@lru_cache(maxsize=1)
def load_catalog() -> RuleCatalog:
    """Load and cache the bundled rule catalog."""

    raw = resources.files("mcpscan.rules").joinpath("catalog.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    return RuleCatalog.model_validate(data)
