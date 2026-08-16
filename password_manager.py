import base64
import json
import os
import uuid
from datetime import datetime, timezone

import tkinter as tk
from tkinter import messagebox

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.enc")
KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536
KDF_PARALLELISM = 4
KDF_HASH_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16
VAULT_VERSION = 1

class VaultError(Exception):
    """vault.enc is missing pieces, malformed, or otherwise unreadable"""

#Crypto/persistence helpers (no GUI)
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

def save_vault(entries: list, key: bytes, salt:bytes) -> None:
    nonce = os.urandom(NONCE_LEN)
    plaintext = json.dumps(entries).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

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
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
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
        with open(VAULT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        raise VaultError(f"Could not read the vault file:\n{exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultError("The vault file is not valid JSON (corrupted?).") from exc

    if not isinstance(data, dict):
        raise VaultError("The vault file is malformed (expected a JSON object).")
    if data.get("version") != VAULT_VERSION or data.get("kdf") != "argon2id":
        raise VaultError("The vault file has an unsupported version or KDF.")

    decoded = {}
    for field, expected_len in (
        ("salt", SALT_LEN),
        ("nonce", NONCE_LEN),
        ("ciphertext", None),
    ):
        value = data.get(field)
        if not isinstance(value, str):
            raise VaultError(f"The vault file is missing the '{field}' field.")
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise VaultError(
                f"The vault file field '{field}' is not valid base64."
            ) from exc
        if expected_len is not None and len(raw) != expected_len:
            raise VaultError(f"The vault file field '{field}' has the wrong length.")
        decoded[field] = raw

    if len(decoded["ciphertext"]) < GCM_TAG_LEN:
        raise VaultError("The vault file ciphertext is too short.")
    return decoded

def decrypt_entries(key: bytes, nonce: bytes, ciphertext: bytes) -> list:
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    try:
        entries = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultError("The decrypted vault contents are not valid JSON.") from exc
    if not isinstance(entries, list):
        raise VaultError("The decrypted vault content are not a list of entries.")
    return entries

#GUI
class PasswordManagerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Archon Password Manager")
        self.root.geometry("560x420")
        self.root.protocol("WM_DELETE_WINDOW", self._lock_and_exit)

        self.key = None
        self.salt = None
        self.entries = []

        self._frame = None
        self.listbox = None

        if os.path.exists(VAULT_PATH):
            self._show_unlock_screen()
        else:
            self._show_create_screen()
    def _set_screen(self, frame: tk.Frame) -> None:
        if self._frame is not None:
            self._frame.destroy()
        self._frame = frame
        frame.pack(fill="both", expand=True, padx=16, pady=16)

    def _busy_cursor(self, busy: bool) -> None:
        try:
            self.root.config(cursor="watch" if busy else "")
            self.root.update_idletasks()
        except tk.TclError:
            pass

    def _show_create_screen(self) -> None:
        frame = tk.Frame(self.root)
        tk.Label(
            frame, text="Create Master Password", font=("TkDefaultFont", 14, "bold")
        ).pack(pady=(0,0))
        tk.Label(
            frame,
            text=(
                "No vault was found. Choose a master password.\n"
                "It protects all entries and cannot be recovered if lost."
            ),
        ).pack(pady=(0,12))

        tk.Label(frame, text="Master Password:").pack(anchor="w")
        self._pw_entry = tk.Entry(frame, show="*", width=36)
        self._pw_entry.pack(pady=(0,8))

        tk.Label(frame, text="Confirm Password:").pack(anchor="w")
        self._confirm_entry = tk.Entry(frame, show="*", width=36)
        self._confirm_entry.pack(pady=(0,12))

        tk.Button(frame, text="Create Vault", command=self._on_create_vault).pack()

        self._pw_entry.focus_set()
        self._pw_entry.bind("<Return>", lambda _e: self._confirm_entry.focus_set())
        self._confirm_entry.bind("<Return>", lambda _e: self._on_create_vault())
        self._set_screen(frame)

    def _on_create_vault(self) -> None:
        pw = self._pw_entry.get()
        confirm = self._confirm_entry.get()
        if not pw:
            messagebox.showerror(
                "Error", "The master password must not be empty.", parent=self.root
            )
            return
        if pw != confirm:
            messagebox.showerror(
                "Error", "The passwords do not match.", parent=self.root
            )
            return

        salt = os.urandom(SALT_LEN)
        self._busy_cursor(True)
        try:
            key = derive_key(pw, salt)
        finally:
            self._busy_cursor(False)

        try:
            save_vault([], key, salt)
        except OSError as exc:
            messagebox.showerror(
                "Error", f"Could not create the vault file:\n{exc}", parent=self.root
            )
            return

        self.key, self.salt, self.entries = key, salt, []
        self._show_main_screen()
    def _show_unlock_screen(self) -> None:
        frame = tk.Frame(self.root)
        tk.Label(
            frame, text="Unlock Vault", font=("TkDefaultFont", 14, "bold")
        ).pack(pady=(0,12))
        tk.Label(frame, text="Enter your master password:").pack(anchor="w")
        self._pw_entry = tk.Entry(frame, show="*", width=36)
        self._pw_entry.pack(pady=(0,12))
        tk.Button(frame, text="Unlock", command=self._on_unlock).pack()

        self._pw_entry.focus_set() 
        self._pw_entry.bind("<Return>", lambda _e: self._on_unlock())
        self._set_screen(frame)
    def _on_unlock(self) -> None:
        pw = self._pw_entry.get()
        if not pw:
            messagebox.showerror(
                "Error", "Please enter your master password.", parent=self.root
            )
            return
        try:
            env = load_vault_file()
        except VaultError as exc:
            messagebox.showerror("Error", str(exc), parent=self.root)
            return

        self._busy_cursor(True)
        try:
            key = derive_key(pw, env["salt"])
        finally:
            self._busy_cursor(False)

        try:
            entries = decrypt_entries(key, env["nonce"], env["ciphertext"])
        except InvalidTag:
            messagebox.showerror(
                "Error", "Incorrect password or corrupted vault file.",
                parent=self.root,
            )
            self._pw_entry.delete(0, tk.END)
            return
        except VaultError as exc:
            messagebox.showerror("Error", str(exc), parent=self.root)
            return
        self.key, self.salt, self.entries = key, env["salt"], entries
        self._show_main_screen()

    def _show_main_screen(self) -> None:
        frame = tk.Frame(self.root)
        tk.Label(
            frame, text="Vault Entries", font=("TkDefaultFont", 12, "bold")
        ).pack(anchor="w")

        list_frame = tk.Frame(frame)
        list_frame.pack(fill="both", expand=True, pady=8)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical")

        self.listbox = tk.Listbox(
            list_frame, exportselection=False, yscrollcommand=scrollbar.set
        )

        scrollbar.config(command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.pack(side="left", fill="both", expand=True)

        buttons = tk.Frame(frame)
        buttons.pack(fill="x")
        tk.Button(buttons, text="Add Entry", command=self._open_add_dialog).pack(
            side="left"
        )
        tk.Button(buttons, text="View Entry", command=self._view_selected).pack(
            side="left", padx=6
        )
        tk.Button(buttons, text="Delete Entry", command=self._delete_selected).pack(
            side="left"
        )
        tk.Button(buttons, text="Lock/Exit", command=self._lock_and_exit).pack(
            side="right"
        )

        self._refresh_listbox()
        self._set_screen(frame)

    def _refresh_listbox(self) -> None:
        self.listbox.delete(0, tk.END)
        for entry in self.entries:
            self.listbox.insert(tk.END, entry.get("title", "(untitled)"))

    def _selected_index(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showinfo(
                "No selection", "Please select an entry first.", parent=self.root
            )
            return None
        return selection[0]
    def _persist(self) -> bool:
        try:
            save_vault(self.entries, self.key, self.salt)
            return True
        except OSError as exc:
            messagebox.showerror(
                "Save failed", f"Could not write the vault file:\n{exc}",
                parent=self.root
            )
            return False

    @staticmethod
    def _toggle_show(entry: tk.Entry, button: tk.Button) -> None:
        if entry.cget("show"):
            entry.config(show="")
            button.config(text="Hide")
        else:
            entry.config(show="*")
            button.config(text="Show")

    @staticmethod
    def _make_modal(dialog: tk.Toplevel) -> None:
        try:
            dialog.wait_visibility()
            dialog.grab_set()
        except tk.TclError:
            pass

    def _open_add_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Entry")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        body = tk.Frame(dialog)
        body.pack(padx=16, pady=16)

        tk.Label(body, text="Title:").grid(row=0, column=0, sticky="e", pady=2)
        self._add_title = tk.Entry(body, width=32)
        self._add_title.grid(row=0, column=1, columnspan=2, sticky="w", pady=2)

        tk.Label(body, text="Username:").grid(row=1, column=0, sticky="e", pady=2)
        self._add_username = tk.Entry(body, width=32)
        self._add_username.grid(row=1, column=1, columnspan=2, sticky="w", pady=2)

        tk.Label(body, text="Password:").grid(row=2, column=0, sticky="e", pady=2)
        self._add_password = tk.Entry(body, width=24, show="*")
        self._add_password.grid(row=2, column=1, sticky="w", pady=2)
        toggle_btn = tk.Button(
            body, text="Show", width=5,
            command=lambda: self._toggle_show(self._add_password, toggle_btn),
        )
        toggle_btn.grid(row=2, column=2, sticky="w", padx=(6,0), pady=2)

        tk.Label(body, text="Notes:").grid(row=3, column=0, sticky="ne", pady=2)
        self._add_notes = tk.Text(body, width=32, height=5)
        self._add_notes.grid(row=3, column=1, columnspan=2, sticky="w", pady=2)

        btns = tk.Frame(dialog)
        btns.pack(pady=(0,12))
        tk.Button(btns, text="Save", width=8, command=self._on_add_save).pack(
            side="left", padx=4
        )
        tk.Button(btns, text="Cancel", width=8, command=dialog.destroy).pack(
            side="left", padx=4
        )

        self._add_dialog = dialog
        self._add_title.focus_set()
        self._make_modal(dialog)

    def _on_add_save(self) -> None:
        title = self._add_title.get().strip()
        if not title:
            messagebox.showerror(
                "Error", "Title must not be empty.", parent=self._add_dialog
            )
            return

        entry = {
            "id": str(uuid.uuid4()),
            "title": title,
            "username": self._add_username.get(),
            "password": self._add_password.get(),

            "notes": self._add_notes.get("1.0", "end-1c"),
            "created": datetime.now(timezone.utc).isoformat(),
        }
        self.entries.append(entry)
        if not self._persist():
            self.entries.pop()
            return
        self._refresh_listbox()
        self._add_dialog.destroy()

    def _view_selected(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        entry = self.entries[index]

        dialog = tk.Toplevel(self.root)
        dialog.title(f"View Entry - {entry.get('title', '')}")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        body = tk.Frame(dialog)
        body.pack(padx=16, pady=16)

        def readonly_row(row: int, label: str, value: str, masked: bool = False):
            tk.Label(body, text=label).grid(row=row, column=0, sticky="e", pady=2)
            field = tk.Entry(body, width=24 if masked else 32)
            field.insert(0, value)
            if masked:
                field.config(show="*")
            field.config(state="readonly")
            field.grid(
                row=row, column=1, columnspan=1 if masked else 2, sticky="w", pady=2
            )
            return field
        readonly_row(0, "Title:", entry.get("title", ""))
        readonly_row(1, "Username:", entry.get("username", ""))
        pw_field = readonly_row(2, "Password:", entry.get("password", ""), masked=True)
        toggle_btn = tk.Button(
            body, text="Show", width=5,
            command=lambda: self._toggle_show(pw_field, toggle_btn),
        )
        toggle_btn.grid(row=2, column=2, sticky="w", padx=(6,0), pady=2)

        tk.Label(body, text="Notes:").grid(row=3, column=0, sticky="ne", pady=2)
        notes = tk.Text(body, width=32, height=5)
        notes.insert("1.0", entry.get("notes", ""))
        notes.config(state="disabled")
        notes.grid(row=3, column=1, columnspan=2, sticky="w", pady=2)

        readonly_row(4, "Created:", entry.get("created", ""))

        tk.Button(dialog, text="Close", width=8, command=dialog.destroy).pack(
            pady=(0,12)
        )
        self._make_modal(dialog)

    def _delete_selected(self) -> None:
        index = self._selected_index()
        if index is None:
            return
        title = self.entries[index].get("title", "(untitled)")
        if not messagebox.askyesno(
            "Confirm Delete",
            f"Delete '{title}'? This cannot be undone.",
            parent=self.root,
        ):
            return
        removed = self.entries.pop(index)
        if not self._persist():
            self.entries.insert(index, removed)
            return
        self._refresh_listbox()

    def _lock_and_exit(self) -> None:
        self.key = None
        self.entries = []
        self.root.destroy()

def main() -> None:
    root = tk.Tk()
    PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()