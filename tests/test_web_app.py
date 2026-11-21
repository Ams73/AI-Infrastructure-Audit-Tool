import unittest
from unittest import mock

from fastapi.testclient import TestClient

from tests.fakes import FakeExecutor, clean_linux_responses
from web.app import app


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_homepage_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Run Audit", response.text)

    def test_run_audit_endpoint(self):
        executor = FakeExecutor(responses=clean_linux_responses("df_pressure.txt"))
        with mock.patch("web.app.build_executor", return_value=executor):
            response = self.client.post("/run", data={"host": "web01", "platform": "linux"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Audit Results", response.text)
        self.assertIn("[FAIL] LNX-DISK-001", response.text)
        self.assertTrue(executor.closed)

    def test_user_input_is_escaped(self):
        executor = FakeExecutor(responses={})
        with mock.patch("web.app.build_executor", return_value=executor):
            response = self.client.post("/run", data={"host": "<script>alert(1)</script>", "platform": "linux"})
        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertIn("&lt;script&gt;", response.text)

    def test_invalid_platform_rejected(self):
        response = self.client.post("/run", data={"host": "web01", "platform": "<b>bsd</b>"})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("<b>bsd</b>", response.text)


if __name__ == "__main__":
    unittest.main()
