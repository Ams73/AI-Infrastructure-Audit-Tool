"""Tests for the AI summary layer. No test calls the real API."""
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from audit_tool import ai_summary as ai
from audit_tool.models import Finding
from audit_tool.redact import make_redactor
from audit_tool.reports import export_findings

try:
    import anthropic
    import httpx
except ImportError:  # the [ai] extra is optional
    anthropic = None


def finding(check_id, status, severity="high", evidence="", accounts=None, host="web01.corp.example.com"):
    return Finding(
        check_id, f"name {check_id}", host, "linux", severity, status, "desc", evidence, "fix it",
        "2026-11-22T00:00:00+00:00", accounts or [],
    )


FINDINGS = [
    finding("LNX-ACCT-001", "fail", evidence="FAIL: accounts other than root have UID 0: toor", accounts=["root", "toor"]),
    finding("LNX-SSH-001", "warn", evidence="Source: /etc/ssh/sshd_config on web01.corp.example.com (10.0.0.5)"),
    finding("LNX-SUDO-001", "error", evidence="/etc/sudoers is not readable"),
    finding("LNX-DISK-001", "pass", "medium", evidence="all fine"),
    finding("LNX-CRON-001", "skipped", "medium"),
]

MODEL_ANSWER = {
    "executive_summary": "Host [HOST-1] has an extra root-equivalent account [USER-1].",
    "overall_risk": "high",
    "priorities": [
        {
            "title": "Remove UID 0 account [USER-1]",
            "check_ids": ["LNX-ACCT-001", "LNX-FAKE-999"],
            "rationale": "A second UID 0 account is full root access.",
            "actions": ["userdel [USER-1] on [HOST-1]"],
            "effort": "low",
        }
    ],
    "coverage_gaps": ["LNX-SUDO-001 could not run; re-run as root."],
}


def fake_response(answer=MODEL_ANSWER, stop_reason="end_turn", model="claude-opus-5-5", stop_details=None):
    text = answer if isinstance(answer, str) else json.dumps(answer)
    return SimpleNamespace(
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        stop_reason=stop_reason,
        stop_details=stop_details,
        model=model,
        usage=SimpleNamespace(input_tokens=1200, output_tokens=300, cache_read_input_tokens=None),
    )


class FakeClient:
    def __init__(self, response=None, error=None):
        self.calls = []
        self.response = response if response is not None else fake_response()
        self.error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class PayloadTests(unittest.TestCase):
    def test_payload_contains_only_attention_findings_in_full(self):
        redactor = ai.payload_redactor(FINDINGS, hosts=[], terms=[])
        payload = ai.build_payload(FINDINGS, redactor)
        self.assertEqual([f["check_id"] for f in payload["findings"]], ["LNX-ACCT-001", "LNX-SSH-001", "LNX-SUDO-001"])
        self.assertEqual(payload["passed_checks"], ["LNX-DISK-001"])
        self.assertEqual(payload["skipped_checks"], ["LNX-CRON-001"])

    def test_payload_is_redacted(self):
        redactor = ai.payload_redactor(FINDINGS, hosts=["web01.corp.example.com"], terms=[])
        dumped = json.dumps(ai.build_payload(FINDINGS, redactor))
        for secret in ("web01", "10.0.0.5", "toor"):
            self.assertNotIn(secret, dumped)
        self.assertIn("root", dumped)  # well-known account kept for meaning

    def test_evidence_can_be_omitted(self):
        redactor = make_redactor()
        payload = ai.build_payload(FINDINGS, redactor, include_evidence=False)
        self.assertFalse(payload["evidence_included"])
        self.assertTrue(all("evidence" not in f for f in payload["findings"]))

    def test_current_user_is_redacted(self):
        with mock.patch("audit_tool.ai_summary.getpass.getuser", return_value="jdoe"):
            redactor = ai.payload_redactor([finding("X", "fail", evidence="owner jdoe")], hosts=[], terms=[])
        self.assertNotIn("jdoe", json.dumps(ai.build_payload([finding("X", "fail", evidence="owner jdoe")], redactor)))


class SummarizeTests(unittest.TestCase):
    def test_request_shape(self):
        client = FakeClient()
        ai.summarize(FINDINGS, client=client, hosts=["web01.corp.example.com"])
        request = client.calls[0]
        self.assertEqual(request["model"], "claude-opus-5-5")
        self.assertEqual(request["output_config"]["effort"], "medium")
        self.assertEqual(request["output_config"]["format"]["type"], "json_schema")
        self.assertEqual(request["fallbacks"], "default")
        self.assertEqual(request["betas"], [ai.FALLBACK_BETA])
        self.assertNotIn("thinking", request)  # adaptive by default on Opus 5.5
        content = request["messages"][0]["content"]
        self.assertTrue(content.startswith("<audit_results>"))
        self.assertNotIn("web01", content)
        self.assertNotIn("toor", content)

    def test_placeholders_are_restored_and_unknown_ids_dropped(self):
        summary = ai.summarize(FINDINGS, client=FakeClient(), hosts=["web01.corp.example.com"])
        self.assertIn("toor", summary.executive_summary)
        self.assertIn("web01.corp.example.com", summary.executive_summary)
        self.assertEqual(summary.priorities[0]["actions"], ["userdel toor on web01.corp.example.com"])
        self.assertEqual(summary.priorities[0]["check_ids"], ["LNX-ACCT-001"])
        self.assertIn("LNX-FAKE-999", summary.notes[0])
        self.assertEqual(summary.usage, {"input_tokens": 1200, "output_tokens": 300})

    def test_no_api_call_when_nothing_needs_attention(self):
        client = FakeClient()
        summary = ai.summarize([finding("A", "pass"), finding("B", "skipped")], client=client)
        self.assertEqual(client.calls, [])
        self.assertEqual(summary.overall_risk, "low")
        self.assertIn("no API call", summary.model)

    def test_models_without_fallback_support_omit_it(self):
        client = FakeClient(fake_response(model="claude-haiku-5-5"))
        ai.summarize(FINDINGS, client=client, model="claude-haiku-5-5", effort="low")
        self.assertNotIn("fallbacks", client.calls[0])
        self.assertNotIn("betas", client.calls[0])

    def test_fallback_model_is_noted(self):
        summary = ai.summarize(FINDINGS, client=FakeClient(fake_response(model="claude-opus-4-8")))
        self.assertEqual(summary.model, "claude-opus-4-8")
        self.assertTrue(any("fallback model claude-opus-4-8" in note for note in summary.notes))

    def test_bad_responses_raise_summary_error(self):
        cases = {
            "declined": fake_response(stop_reason="refusal", stop_details=SimpleNamespace(category="cyber")),
            "cut off": fake_response(stop_reason="max_tokens"),
            "not valid JSON": fake_response(answer="not json"),
            "missing fields": fake_response(answer={"executive_summary": "x"}),
        }
        for expected, response in cases.items():
            with self.subTest(expected=expected), self.assertRaises(ai.AISummaryError) as ctx:
                ai.summarize(FINDINGS, client=FakeClient(response))
            self.assertIn(expected.split()[0], str(ctx.exception))

    def test_invalid_effort(self):
        with self.assertRaises(ai.AISummaryError):
            ai.summarize(FINDINGS, client=FakeClient(), effort="extreme")


class ReportRenderingTests(unittest.TestCase):
    def setUp(self):
        self.summary = ai.summarize(FINDINGS, client=FakeClient(), hosts=["web01.corp.example.com"])

    def test_markdown_section(self):
        rendered = export_findings(FINDINGS, "markdown", ai_summary=self.summary)
        self.assertIn("## AI summary", rendered)
        self.assertIn("AI-generated", rendered)
        self.assertIn("**Overall risk: high**", rendered)
        self.assertIn("1. **Remove UID 0 account toor** (`LNX-ACCT-001`; effort: low)", rendered)
        self.assertLess(rendered.index("## AI summary"), rendered.index("## Findings requiring attention"))

    def test_text_and_json(self):
        text = export_findings(FINDINGS, "text", ai_summary=self.summary)
        self.assertIn("AI summary by claude-opus-5-5", text)
        self.assertIn("1. Remove UID 0 account toor [LNX-ACCT-001] (effort: low)", text)
        payload = json.loads(export_findings(FINDINGS, "json", ai_summary=self.summary))
        self.assertEqual(payload["ai_summary"]["overall_risk"], "high")
        self.assertIn("disclaimer", payload["ai_summary"])

    def test_reports_unchanged_without_summary(self):
        self.assertNotIn("AI summary", export_findings(FINDINGS, "markdown"))
        self.assertNotIn("ai_summary", json.loads(export_findings(FINDINGS, "json")))


@unittest.skipIf(anthropic is None, "anthropic SDK not installed (pip install .[ai])")
class RealSdkTests(unittest.TestCase):
    """Drive the real Anthropic SDK against a mocked HTTP transport, so request
    serialization and response parsing are checked without network access."""

    def client(self, handler):
        return anthropic.Anthropic(
            api_key="test-key", max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(handler))
        )

    def test_end_to_end_request_and_response(self):
        seen = {}

        def handler(request):
            seen["headers"] = request.headers
            seen["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-opus-5-5",
                    "content": [{"type": "text", "text": json.dumps(MODEL_ANSWER)}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1500, "output_tokens": 420},
                },
            )

        summary = ai.summarize(FINDINGS, client=self.client(handler), hosts=["web01.corp.example.com"])
        self.assertIn(ai.FALLBACK_BETA, seen["headers"]["anthropic-beta"])
        body = seen["body"]
        self.assertEqual(body["fallbacks"], "default")
        self.assertEqual(body["output_config"]["format"]["schema"], ai.SUMMARY_SCHEMA)
        self.assertNotIn("toor", json.dumps(body))
        self.assertEqual(summary.priorities[0]["check_ids"], ["LNX-ACCT-001"])
        self.assertEqual(summary.usage["output_tokens"], 420)

    def test_refusal_is_reported(self):
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                    "content": [], "stop_reason": "refusal", "stop_sequence": None,
                    "stop_details": {"type": "refusal", "category": "cyber", "explanation": "declined"},
                    "usage": {"input_tokens": 10, "output_tokens": 0},
                },
            )

        with self.assertRaises(ai.AISummaryError) as ctx:
            ai.summarize(FINDINGS, client=self.client(handler))
        self.assertIn("cyber", str(ctx.exception))

    def test_http_errors_are_mapped(self):
        cases = [
            (401, {}, "authentication failed"),
            (404, {}, "was not found"),
            (429, {"retry-after": "30"}, "retry after 30s"),
            (529, {}, "API error 529"),
        ]
        for status, headers, expected in cases:
            def handler(request, status=status, headers=headers):
                return httpx.Response(
                    status, headers=headers, json={"type": "error", "error": {"type": "x", "message": "boom"}}
                )

            with self.subTest(status=status), self.assertRaises(ai.AISummaryError) as ctx:
                ai.summarize(FINDINGS, client=self.client(handler))
            self.assertIn(expected, str(ctx.exception))

    def test_missing_credentials(self):
        clean_env = {k: v for k, v in __import__("os").environ.items() if not k.startswith("ANTHROPIC_")}
        with mock.patch.dict("os.environ", clean_env, clear=True):
            client = anthropic.Anthropic(api_key=None, max_retries=0)
            with self.assertRaises(ai.AISummaryError) as ctx:
                ai.summarize(FINDINGS, client=client)
        self.assertIn("no Anthropic API credentials", str(ctx.exception))

    def test_network_failure(self):
        def handler(request):
            raise httpx.ConnectError("no route to host")

        with self.assertRaises(ai.AISummaryError) as ctx:
            ai.summarize(FINDINGS, client=self.client(handler))
        self.assertIn("could not reach", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
