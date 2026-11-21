import unittest

from audit_tool.redact import make_redactor


class RedactorTests(unittest.TestCase):
    def test_hosts_are_pseudonymized_consistently_and_restorable(self):
        redactor = make_redactor(hosts=["web01.corp.example.com"])
        text = "Connected to web01.corp.example.com; WEB01 reported an error"
        redacted = redactor.redact(text)
        self.assertNotIn("web01", redacted.lower())
        self.assertEqual(redactor.restore(redacted).lower(), text.lower())
        # Same value, same placeholder, across calls.
        self.assertEqual(redactor.redact("web01.corp.example.com"), redactor.redact("web01.corp.example.com"))

    def test_network_identifiers(self):
        redactor = make_redactor()
        text = "from 10.0.12.7 and 2001:db8::8a2e:370:7334 mac 00:1A:2B:3C:4D:5E mail ops@example.com"
        redacted = redactor.redact(text)
        for secret in ("10.0.12.7", "2001:db8", "00:1A:2B", "ops@example.com"):
            self.assertNotIn(secret, redacted)
        self.assertEqual(redactor.restore(redacted), text)

    def test_versions_times_and_ssh_algorithms_are_kept(self):
        redactor = make_redactor()
        text = "Kernel: 6.18.58.1-microsoft-standard-WSL2 at 10:00:00 cipher aes128-gcm@openssh.com"
        self.assertEqual(redactor.redact(text), text)

    def test_windows_identities(self):
        redactor = make_redactor()
        text = "CONTOSO\\svc_backup S-1-5-21-1111111111-2222222222-3333333333-500 C:\\Users\\jdoe\\Desktop"
        redacted = redactor.redact(text)
        self.assertNotIn("CONTOSO", redacted)
        self.assertNotIn("1111111111", redacted)
        self.assertNotIn("jdoe", redacted)
        self.assertIn("-500", redacted)  # well-known RID kept: it means "built-in Administrator"
        self.assertIn("C:\\Users\\[USER-1]", redacted)

    def test_paths_are_not_mistaken_for_domains(self):
        redactor = make_redactor()
        text = "At C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\BitLocker.psm1"
        self.assertEqual(redactor.redact(text), text)

    def test_secrets_and_keys(self):
        redactor = make_redactor()
        text = (
            "password=hunter2 api_key: 'abc123'\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3Nza\n-----END OPENSSH PRIVATE KEY-----"
        )
        redacted = redactor.redact(text)
        for secret in ("hunter2", "abc123", "AAAAB3Nza"):
            self.assertNotIn(secret, redacted)
        self.assertIn("password=[SECRET-1]", redacted)

    def test_accounts_redacted_but_well_known_names_kept(self):
        redactor = make_redactor(accounts=["toor", "helpdesk", "%ops", "root", "Administrator"])
        text = "uid0: root, toor; '%ops' and helpdesk; built-in Administrator enabled"
        redacted = redactor.redact(text)
        self.assertNotIn("toor", redacted)
        self.assertNotIn("helpdesk", redacted)
        self.assertIn("[GROUP-1]", redacted)
        self.assertIn("root", redacted)
        self.assertIn("Administrator", redacted)

    def test_extra_terms(self):
        redactor = make_redactor(terms=["Acme Corp"])
        self.assertEqual(redactor.redact("Owned by Acme Corp."), "Owned by [TERM-1].")

    def test_localhost_and_empty_values_are_ignored(self):
        redactor = make_redactor(hosts=["localhost", "", None], accounts=["", "x"])
        self.assertEqual(redactor.redact("localhost x"), "localhost x")

    def test_restore_all_handles_nested_structures(self):
        redactor = make_redactor(hosts=["db01"])
        placeholder = redactor.redact("db01")
        data = {"a": [placeholder, {"b": f"fix {placeholder}"}], "n": 3}
        self.assertEqual(redactor.restore_all(data), {"a": ["db01", {"b": "fix db01"}], "n": 3})

    def test_unknown_placeholders_are_left_alone(self):
        self.assertEqual(make_redactor().restore("see [HOST-9]"), "see [HOST-9]")


if __name__ == "__main__":
    unittest.main()
