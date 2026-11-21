import unittest
from unittest import mock

from fastapi.testclient import TestClient

from tests.fakes import FIXTURE_DATE, FakeExecutor, clean_linux_responses
from web.app import SECURITY_HEADERS, Target, WebSettings, create_app, parse_targets

USER, PASSWORD = "auditor", "correct-horse-battery"
AUTH = (USER, PASSWORD)


def make_client(**overrides):
    values = dict(
        username=USER,
        password=PASSWORD,
        targets=[Target("localhost"), Target("web01", "linux", "svc_audit")],
    )
    values.update(overrides)
    settings = WebSettings(**values)
    app = create_app(settings)
    return TestClient(app), settings, app


class TargetParsingTests(unittest.TestCase):
    def test_valid_spec(self):
        targets = parse_targets(" localhost, web01:linux:auditor ,win01:windows:CORP\\auditor,")
        self.assertEqual(
            targets,
            [
                Target("localhost"),
                Target("web01", "linux", "auditor"),
                Target("win01", "windows", "CORP\\auditor"),
            ],
        )
        self.assertEqual(parse_targets(""), [])

    def test_invalid_specs(self):
        for spec in ("web01", "web01:solaris", ":linux"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                parse_targets(spec)

    def test_settings_from_env(self):
        settings = WebSettings.from_env(
            {"AUDIT_WEB_USERNAME": "u", "AUDIT_WEB_PASSWORD": "p" * 12, "AUDIT_WEB_TARGETS": "localhost"}
        )
        self.assertIsNone(settings.auth_problem)
        self.assertEqual(settings.targets, [Target("localhost")])


class AuthenticationTests(unittest.TestCase):
    def test_locked_until_credentials_configured(self):
        client, _, _ = make_client(username="", password="")
        self.assertEqual(client.get("/", auth=AUTH).status_code, 503)
        self.assertEqual(client.post("/run", auth=AUTH).status_code, 503)

    def test_short_password_keeps_ui_locked(self):
        client, _, _ = make_client(password="short")
        response = client.get("/", auth=(USER, "short"))
        self.assertEqual(response.status_code, 503)
        self.assertIn("at least 12", response.text)

    def test_missing_or_wrong_credentials_rejected(self):
        client, _, _ = make_client()
        for auth in (None, (USER, "wrong-password!"), ("someone", PASSWORD)):
            with self.subTest(auth=auth):
                response = client.get("/", auth=auth)
                self.assertEqual(response.status_code, 401)
                self.assertIn("Basic", response.headers["WWW-Authenticate"])

    def test_security_headers_on_every_response(self):
        client, _, _ = make_client()
        for response in (client.get("/"), client.get("/", auth=AUTH)):
            for header, value in SECURITY_HEADERS.items():
                self.assertEqual(response.headers.get(header), value)

    def test_api_docs_are_disabled(self):
        client, _, _ = make_client()
        for path in ("/docs", "/openapi.json", "/redoc"):
            self.assertEqual(client.get(path, auth=AUTH).status_code, 404)


class AuditFormTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("audit_tool.checks.linux._today", return_value=FIXTURE_DATE)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_form_offers_only_configured_targets(self):
        client, settings, _ = make_client()
        response = client.get("/", auth=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertIn("web01 (linux) as svc_audit", response.text)
        self.assertIn(settings.csrf_token, response.text)
        self.assertNotIn('name="host"', response.text)  # no free-text host field

    def test_no_targets_configured(self):
        client, _, _ = make_client(targets=[])
        self.assertIn("No audit targets are configured", client.get("/", auth=AUTH).text)

    def test_target_labels_are_escaped(self):
        client, _, _ = make_client(targets=[Target("<script>x</script>", "linux")])
        text = client.get("/", auth=AUTH).text
        self.assertNotIn("<script>x</script>", text)
        self.assertIn("&lt;script&gt;", text)

    def test_runs_audit_on_selected_target(self):
        client, settings, _ = make_client()
        executor = FakeExecutor(responses=clean_linux_responses("df_pressure.txt"))
        with mock.patch("web.app.build_executor", return_value=executor) as build:
            response = client.post("/run", auth=AUTH, data={"target": "1", "csrf_token": settings.csrf_token})
        self.assertEqual(response.status_code, 200)
        self.assertIn("[FAIL] LNX-DISK-001", response.text)
        kwargs = build.call_args.kwargs
        self.assertEqual((kwargs["host"], kwargs["platform"], kwargs["username"]), ("web01", "linux", "svc_audit"))
        self.assertTrue(executor.closed)

    def test_csrf_token_required(self):
        client, _, _ = make_client()
        with mock.patch("web.app.build_executor") as build:
            for token in (None, "", "forged"):
                data = {"target": "1"} if token is None else {"target": "1", "csrf_token": token}
                with self.subTest(token=token):
                    self.assertEqual(client.post("/run", auth=AUTH, data=data).status_code, 403)
        build.assert_not_called()

    def test_unknown_targets_rejected(self):
        client, settings, _ = make_client()
        with mock.patch("web.app.build_executor") as build:
            for target in ("2", "-1", "abc", "²", "", "web01"):
                with self.subTest(target=target):
                    data = {"target": target, "csrf_token": settings.csrf_token}
                    self.assertEqual(client.post("/run", auth=AUTH, data=data).status_code, 400)
        build.assert_not_called()

    def test_one_audit_at_a_time(self):
        client, settings, app = make_client()
        app.state.audit_lock.acquire()
        try:
            with mock.patch("web.app.build_executor") as build:
                response = client.post("/run", auth=AUTH, data={"target": "0", "csrf_token": settings.csrf_token})
            self.assertEqual(response.status_code, 429)
            build.assert_not_called()
        finally:
            app.state.audit_lock.release()

    def test_lock_released_after_failure(self):
        client, settings, app = make_client()
        with mock.patch("web.app.build_executor", side_effect=ValueError("bad target")):
            response = client.post("/run", auth=AUTH, data={"target": "0", "csrf_token": settings.csrf_token})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(app.state.audit_lock.locked())

    def test_csrf_token_differs_per_server_instance(self):
        _, first, _ = make_client()
        _, second, _ = make_client()
        self.assertNotEqual(first.csrf_token, second.csrf_token)


if __name__ == "__main__":
    unittest.main()
