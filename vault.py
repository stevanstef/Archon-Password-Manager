import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import (
    GCM_TAG_LEN,
    KDF_MEMORY_COST,
    KDF_PARALLELISM,
    KDF_TIME_COST,
    NONCE_LEN,
    SALT_LEN,
    VAULT_PATH,
    VAULT_VERSION,
)

class VaultError(Exception):
    """vault.enc is missing pieces, malformed, or otherwise unreadable."""

def save_vault(entries: list, key: bytes, salt: bytes) -> None:
    nonce = os.urandom(NONCE_LEN)

    plaintext = json.dumps(entries).encode("utf-8")

    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        None,
    )

    envelope = {
        "version": VAULT_VERSION,
        "kdf": "argon2id",
        "kdf_params": {
            "time_cost": KDF_TIME_COST,
            "memory_cost": KDF_MEMORY_COST,
            "parallelism": KDF_PARALLELISM,
        },
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    tmp_path = VAULT_PATH + ".tmp"

    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )

    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass

    os.replace(tmp_path, VAULT_PATH)

    try:
        os.chmod(VAULT_PATH, 0o600)
    except OSError:
        pass

def load_vault_file() -> dict:
    try:
        with open(
            VAULT_PATH,
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

    except OSError as exc:
        raise VaultError(
            f"Could not read the vault file:\n{exc}"
        ) from exc

    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise VaultError(
            "The vault file is not valid JSON (corrupted?)."
        ) from exc

    if not isinstance(data, dict):
        raise VaultError(
            "The vault file is malformed (expected a JSON object)."
        )

    if (
        data.get("version") != VAULT_VERSION
        or data.get("kdf") != "argon2id"
    ):
        raise VaultError(
            "The vault file has an unsupported version or KDF."
        )

    decoded = {}

    for field, expected_len in (
        ("salt", SALT_LEN),
        ("nonce", NONCE_LEN),
        ("ciphertext", None),
    ):
        value = data.get(field)

        if not isinstance(value, str):
            raise VaultError(
                f"The vault file is missing the '{field}' field."
            )

        try:
            raw = base64.b64decode(
                value,
                validate=True,
            )
        except ValueError as exc:
            raise VaultError(
                f"The vault file field '{field}' is not valid base64."
            ) from exc

        if (
            expected_len is not None
            and len(raw) != expected_len
        ):
            raise VaultError(
                f"The vault file field '{field}' has the wrong length."
            )

        decoded[field] = raw

    if len(decoded["ciphertext"]) < GCM_TAG_LEN:
        raise VaultError(
            "The vault file ciphertext is too short."
        )

    return decoded

def decrypt_entries(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> list:
    plaintext = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        None,
    )

    try:
        entries = json.loads(
            plaintext.decode("utf-8")
        )

    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise VaultError(
            "The decrypted vault contents are not valid JSON."
        ) from exc

    if not isinstance(entries, list):
        raise VaultError(
            "The decrypted vault content are not a list of entries."
        )

    return entries