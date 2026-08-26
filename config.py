import os

VAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "vault.enc",
)

KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536
KDF_PARALLELISM = 4
KDF_HASH_LEN = 32

SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16

VAULT_VERSION = 1

PASSWORD_LENGTH = 20
PASSWORD_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

PASSWORD_FIELD_WIDTH = 24
SHOW_BUTTON_WIDTH = 7
GENERATE_BUTTON_WIDTH = 11