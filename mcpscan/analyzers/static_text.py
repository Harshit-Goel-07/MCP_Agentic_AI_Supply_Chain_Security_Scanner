"""Static text analysis of tool descriptions.

Detects the most common, high-signal tool-poisoning primitives that require no ML:

* Hidden / invisible Unicode (zero-width, bidi controls, tag characters).
* Homoglyph (mixed-script) obfuscation.
* Chat-template special-token injection (e.g. ``<|im_start|>``, ``[INST]``).
* Direct prompt-injection / instruction-override phrasing.

Every finding carries the exact character span so the report can highlight the offending text.
"""

from __future__ import annotations

import re
import unicodedata

from mcpscan.analyzers.base import ScanContext
from mcpscan.config import Severity
from mcpscan.models import EvidenceLocation, Finding, ToolModel

# Invisible / control characters frequently used to smuggle instructions.
_INVISIBLE = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
}

_SPECIAL_TOKENS = [
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|system\|>",
    r"<\|endoftext\|>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"</s>",
    r"<s>",
]

_INJECTION_PATTERNS = [
    r"ignore (all |the )?(previous|prior|above) (instructions|prompts)",
    r"disregard (all |the )?(previous|prior|system) (instructions|prompts)",
    r"do not (tell|inform|mention to) the user",
    r"without (asking|informing|telling) the user",
    r"you (are|act as) (a )?(dan|developer mode|unrestricted)",
    r"exfiltrat",
    r"send (the |all )?(secrets|credentials|tokens|env(ironment)? variables)",
    r"read( the)? \.env",
    r"<important>|<secret>|<system>",
]

_TAG_RANGE = range(0xE0000, 0xE0080)


class StaticTextAnalyzer:
    id = "static_text"

    def analyze(self, tool: ToolModel, ctx: ScanContext) -> list[Finding]:
        text = tool.description or ""
        findings: list[Finding] = []
        findings.extend(self._invisible(tool, text))
        findings.extend(self._homoglyphs(tool, text))
        findings.extend(self._special_tokens(tool, text))
        findings.extend(self._injection(tool, text))
        return findings

    def _invisible(self, tool: ToolModel, text: str) -> list[Finding]:
        flagged: list[str] = []
        for idx, char in enumerate(text):
            if char in _INVISIBLE:
                flagged.append(f"U+{ord(char):04X} {_INVISIBLE[char]} @ {idx}")
            elif ord(char) in _TAG_RANGE:
                flagged.append(f"U+{ord(char):06X} TAG CHARACTER @ {idx}")
        if not flagged:
            return []
        return [
            Finding(
                rule_id="MCP-TP-003",
                owasp_mcp_id="MCP-03",
                severity=Severity.HIGH,
                tool=tool.qualified_name,
                server=tool.server,
                title="Hidden Unicode in tool description",
                message="Tool description contains invisible/control characters that can smuggle hidden instructions.",
                location=EvidenceLocation(field="description"),
                evidence={"unicode_flags": flagged},
            )
        ]

    def _homoglyphs(self, tool: ToolModel, text: str) -> list[Finding]:
        scripts = set()
        for char in text:
            if char.isalpha():
                try:
                    name = unicodedata.name(char)
                except ValueError:
                    continue
                scripts.add(name.split(" ")[0])
        suspicious = {"CYRILLIC", "GREEK"} & scripts
        if suspicious and "LATIN" in scripts:
            return [
                Finding(
                    rule_id="MCP-TP-004",
                    owasp_mcp_id="MCP-03",
                    severity=Severity.MEDIUM,
                    tool=tool.qualified_name,
                    server=tool.server,
                    title="Mixed-script (homoglyph) text",
                    message="Description mixes Latin with look-alike scripts; possible homoglyph obfuscation.",
                    location=EvidenceLocation(field="description"),
                    evidence={"scripts": sorted(scripts)},
                )
            ]
        return []

    def _special_tokens(self, tool: ToolModel, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in _SPECIAL_TOKENS:
            match = re.search(pattern, text)
            if match:
                findings.append(
                    Finding(
                        rule_id="MCP-TP-005",
                        owasp_mcp_id="MCP-03",
                        severity=Severity.HIGH,
                        tool=tool.qualified_name,
                        server=tool.server,
                        title="Chat-template special-token injection",
                        message=f"Description embeds a model special token: {match.group(0)!r}.",
                        location=EvidenceLocation(field="description", span=match.span()),
                        evidence={"token": match.group(0)},
                    )
                )
        return findings

    def _injection(self, tool: ToolModel, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lowered = text.lower()
        for pattern in _INJECTION_PATTERNS:
            match = re.search(pattern, lowered)
            if match:
                findings.append(
                    Finding(
                        rule_id="MCP-TP-001",
                        owasp_mcp_id="MCP-01",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        tool=tool.qualified_name,
                        server=tool.server,
                        title="Prompt-injection / tool-poisoning phrasing",
                        message="Description contains instruction-override or exfiltration phrasing.",
                        location=EvidenceLocation(field="description", span=match.span()),
                        evidence={"snippet": text[match.start() : match.end() + 40]},
                    )
                )
        return findings
