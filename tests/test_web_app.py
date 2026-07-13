import unittest

from fastapi.testclient import TestClient

from web.app import app


class WebAppTests(unittest.TestCase):
    def test_homepage_loads(self):
        client = TestClient(app)
        response = client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_run_audit_endpoint(self):
        client = TestClient(app)
        response = client.post("/run", data={"host": "demo", "platform": "linux"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Audit Results", response.text)


if __name__ == "__main__":
    unittest.main()
