# Archon Password Manager
A local desktop password manager built with Python and ttkbootstrap. Entries are encrypted and stored in a single vault file on disk. No cloud, no accounts, no network calls.

## Features
- Master password unlocks the vault
- Vault encrypted at rest with AES-GCM; decrypted only in memory after unlock
- Add, view, edit, delete entries (title, username, password, notes)
- Built-in password generator
- Show/hide toggle for password fields
- Search entries by title
- Light/dark theme toggle

## Requirements
- Python 3.9+
- `ttkbootstrap`
- `cryptography`

```bash
pip install ttkbootstrap cryptography
```

## Usage
Run the app:

```bash
python main.py
```

- First run: no vault exists yet, so you'll be prompted to create a master password. This derives the encryption key. There is no recovery mechanism so if you lose the password, the vault is unrecoverable.
- Subsequent runs: enter the master password to unlock the existing vault.
- Once unlocked:
  - **Add Entry** — create a new entry
  - Double-click an entry, or select it and click **View Entry** — see its details
  - **Edit** (inside the entry view) — modify an entry
  - **Delete Entry** — remove an entry
  - Search box filters entries by title
  - Toggle in the corner switches light/dark theme

## Security Model
- The master password is never stored. It's passed through a key-derivation function with a random salt to produce the encryption key.
- All entries are serialized and encrypted together with AES-GCM before being written to the vault file.
- An incorrect password fails decryption (`InvalidTag`) rather than partially succeeding so there's no way to brute-force feedback from a wrong guess.

## Project Structure
| File | Purpose |
|------|---------|
| `main.py` | GUI application — screens, dialogs, interaction logic |
| `vault.py` | Vault load/save and encryption/decryption |
| `security.py` | Key derivation and password generation |
| `config.py` | Shared constants (paths, sizes, lengths) |

## Notes
- No password recovery. Losing the master password means losing the vault.
- Back up the vault file yourself; there's no built-in backup or sync.
- Intended for single-user, local use — not designed for multi-device sync or team sharing.

Stevan Stefanovic — 2026
