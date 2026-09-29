import unittest

from app import app


class LocalLabTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_idor_returns_only_seeded_synthetic_profile(self):
        response = self.client.get("/api/idor/profile?user_id=1002")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["private_note"], "Synthetic secret: ORBIT-42")
        self.assertEqual(self.client.get("/api/idor/profile?user_id=9999").status_code, 404)

    def test_sql_injection_affects_only_in_memory_training_accounts(self):
        response = self.client.post(
            "/api/sqli/search",
            json={"username": "' OR '1'='1' --", "pin": "x"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["count"], 3)
        self.assertTrue(all(row["username"] in {"mira", "owen", "admin"} for row in response.json["results"]))

    def test_command_injection_simulator_runs_normal_synthetic_lookup(self):
        response = self.client.post("/api/cmdi/run", json={"username": "mira"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["command_count"], 1)
        self.assertFalse(response.json["note_exposed"])
        self.assertEqual(response.json["results"][0]["output"], "Mira Chen · Design")

    def test_command_injection_simulator_lists_fake_training_files(self):
        response = self.client.post(
            "/api/cmdi/run", json={"username": "mira; ls"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["note_exposed"])
        self.assertEqual(response.json["results"][1]["output"], "show-training-note")

    def test_command_injection_simulator_reads_fake_training_note(self):
        response = self.client.post(
            "/api/cmdi/run", json={"username": "mira; cat show-training-note"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["note_exposed"])
        self.assertEqual(response.json["results"][1]["output"], "Synthetic training note: CEDAR-17")

    def test_command_injection_simulator_blocks_unlisted_actions(self):
        response = self.client.post(
            "/api/cmdi/run", json={"username": "mira; whoami"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["note_exposed"])
        self.assertIn("blocked", response.json["results"][1]["output"])

    def test_predictable_reset_token_is_confined_to_toy_account(self):
        response = self.client.post(
            "/api/auth/reset-password",
            json={"username": "admin", "token": "reset-admin", "new_password": "practice-only"},
        )
        self.assertEqual(response.status_code, 200)
        login = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": "practice-only"}
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json["flag"], "VULNLAB{reset_tokens_should_be_random}")

    def test_xss_endpoint_reflects_input_for_sandbox_lesson(self):
        response = self.client.get("/api/xss/render?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        self.assertEqual(response.status_code, 200)
        self.assertIn("<script>alert(1)</script>", response.json["html"])

    def test_home_page_contains_local_only_training_notice(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"RUNNING LOCALLY", response.data)
        self.assertIn(b"NO EXTERNAL TARGETS", response.data)


if __name__ == "__main__":
    unittest.main()
