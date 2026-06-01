import os
from cryptography.fernet import Fernet

_fernet = None

def get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        # Correspond exactement à ce que nous avons mis dans le fichier .env
        key = os.environ.get("FIELD_ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("FIELD_ENCRYPTION_KEY manquante dans .env")
        _fernet = Fernet(key.encode())
    return _fernet

def encrypt(text: str) -> str:
    if not text:
        return text
    return get_fernet().encrypt(text.encode()).decode()

def decrypt(text: str) -> str:
    if not text:
        return text
    try:
        return get_fernet().decrypt(text.encode()).decode()
    except Exception as e:
        print(f"[Crypto] Erreur de déchiffrement: {e}")
        return "[Erreur : Impossible de déchiffrer la donnée]"