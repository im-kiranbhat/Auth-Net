import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import auth_server

class AuthProtocolTests(unittest.TestCase):
    def test_password_record_verifies(self):
        record = auth_server.password_record("correct horse")
        self.assertTrue(auth_server.verify_password("correct horse", record))
        self.assertFalse(auth_server.verify_password("wrong", record))

    def test_salts_differ(self):
        a = auth_server.password_record("same password")
        b = auth_server.password_record("same password")
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertEqual(a["hash"], b["hash"]) if a["salt"] == b["salt"] else None

    def test_demo_users_exist(self):
        self.assertIn("alice", auth_server.USERS)
        self.assertIn("bob", auth_server.USERS)

if __name__ == "__main__":
    unittest.main()
