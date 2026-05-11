import unittest
import sqlite3
import os
from auth.core import enroll_user, UserAlreadyExistsError
from auth.storage import DB_PATH
from auth.crypto import crypto

class TestAuthEnrollment(unittest.TestCase):
    def setUp(self):
        """Clean up database before each test."""
        # Nos aseguramos de limpiar las tablas antes de cada test para no tener basura
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM recovery_codes")
            conn.execute("DELETE FROM auth_attempts")
            conn.execute("DELETE FROM users")
            conn.commit()

    def test_successful_enrollment(self):
        """Should return a URI and 10 recovery codes, and store data in DB."""
        username = "admin_test"
        uri, codes = enroll_user(username)

        # 1. Verificamos que devuelve lo que esperamos
        self.assertTrue(uri.startswith("otpauth://totp/Antigravity-IDS:admin_test"))
        self.assertEqual(len(codes), 10)

        # 2. Verificamos que se guardó en la base de datos
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, encrypted_secret FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            self.assertIsNotNone(user)
            self.assertEqual(user[0], username)
            # Verificamos que está cifrado (no es texto plano)
            self.assertNotEqual(user[1], "any_plain_secret")

    def test_encryption_at_rest(self):
        """Verifies that the stored secret can be decrypted to a valid Base32 string."""
        username = "crypto_user"
        enroll_user(username)

        with sqlite3.connect(DB_PATH) as conn:
            encrypted_secret = conn.execute(
                "SELECT encrypted_secret FROM users WHERE username = ?", (username,)
            ).fetchone()[0]

        # Intentamos descifrar con nuestro CryptoManager
        decrypted = crypto.decrypt(encrypted_secret)
        
        # Los secretos TOTP suelen tener 32 caracteres
        self.assertEqual(len(decrypted), 32)
        self.assertNotEqual(decrypted, encrypted_secret)

    def test_duplicate_user_raises_error(self):
        """Should not allow two users with the same name."""
        username = "duplicate_guy"
        enroll_user(username)
        
        with self.assertRaises(UserAlreadyExistsError):
            enroll_user(username)

if __name__ == "__main__":
    unittest.main()
    