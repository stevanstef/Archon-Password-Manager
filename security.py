import secrets
import string

from argon2.low_level import Type, hash_secret_raw

from config import (
    KDF_HASH_LEN,
    KDF_MEMORY_COST,
    KDF_PARALLELISM,
    KDF_TIME_COST,
    PASSWORD_LENGTH,
    PASSWORD_SYMBOLS,
)

def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=KDF_TIME_COST,
        memory_cost=KDF_MEMORY_COST,
        parallelism=KDF_PARALLELISM,
        hash_len=KDF_HASH_LEN,
        type=Type.ID,
    )

def generate_password(length=PASSWORD_LENGTH) -> str:
    alphabet = (
        string.ascii_letters
        + string.digits
        + PASSWORD_SYMBOLS
    )

    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(PASSWORD_SYMBOLS),
    ]

    password.extend(
        secrets.choice(alphabet)
        for _ in range(length - len(password))
    )

    secrets.SystemRandom().shuffle(password)

    return "".join(password)