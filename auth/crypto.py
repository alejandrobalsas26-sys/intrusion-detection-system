import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Ensure env is loaded for standalone testing
load_dotenv()

class CryptoManager:
    """
    Handles symmetric encryption for TOTP secrets using Fernet (AES-128-CBC + HMAC).
    """
    def __init__(self):
        key = os.getenv("MFA_ENCRYPTION_KEY")
        if not key or key == "your_fernet_key_here":
            raise ValueError(
                "MFA_ENCRYPTION_KEY is missing or not configured in .env. "
                "Generate one using: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )
        
        try:
            self.cipher = Fernet(key.encode())
        except Exception as e:
            raise ValueError(f"Invalid MFA_ENCRYPTION_KEY: {e}")

    def encrypt(self, plain_text: str) -> str:
        """Encrypts a string and returns a URL-safe base64 string."""
        if not plain_text:
            raise ValueError("Cannot encrypt empty text")
        return self.cipher.encrypt(plain_text.encode()).decode()

    def decrypt(self, encrypted_text: str) -> str:
        """Decrypts a Fernet token and returns the original string."""
        if not encrypted_text:
            raise ValueError("Cannot decrypt empty text")
        return self.cipher.decrypt(encrypted_text.encode()).decode()

# Singleton instance for the module
crypto = CryptoManager()
