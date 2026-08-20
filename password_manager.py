import base64
import json
import os
import secrets
import string
import uuid
from datetime import datetime, timezone

import tkinter as tk
from tkinter import messagebox

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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

# Password-field/button geometry used by the Add and View/Edit dialogs.
PASSWORD_FIELD_WIDTH = 24
SHOW_BUTTON_WIDTH = 7
GENERATE_BUTTON_WIDTH = 11


class VaultError(Exception):
    """vault.enc is missing pieces, malformed, or otherwise unreadable."""


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
    alphabet = string.ascii_letters + string.digits + PASSWORD_SYMBOLS

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


def save_vault(entries: list, key: bytes, salt: bytes) -> None:
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
        with open(VAULT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        raise VaultError(
            f"Could not read the vault file:\n{exc}"
        ) from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
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
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise VaultError(
                f"The vault file field '{field}' is not valid base64."
            ) from exc

        if expected_len is not None and len(raw) != expected_len:
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
        entries = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultError(
            "The decrypted vault contents are not valid JSON."
        ) from exc

    if not isinstance(entries, list):
        raise VaultError(
            "The decrypted vault content are not a list of entries."
        )

    return entries


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Archon Password Manager")
        self.root.protocol("WM_DELETE_WINDOW", self._lock_and_exit)

        self.btns = []
        self.key = None
        self.salt = None
        self.entries = []
        self._frame = None
        self.listbox = None

        self._configure_button_styles()

        self._theme_switch = ttk.Checkbutton(
            self.root,
            text="",
            bootstyle="success-round-toggle",
            command=self._toggle_theme,
        )
        self._theme_switch.grid(
            column=1,
            row=99,
            sticky="e",
            padx=10,
            pady=10,
        )

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.grid(
            row=99,
            column=0,
            sticky="sw",
            padx=1,
            pady=1,
        )

        ttk.Label(
            bottom_frame,
            text="© 2026 Stevan Stefanovic",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left")

        if os.path.exists(VAULT_PATH):
            self._show_unlock_screen()
        else:
            self._show_create_screen()

    def _configure_button_styles(self):
        style = self.root.style
        colors = style.colors

        definitions = {
            "SmallPrimary.TButton": colors.primary,
            "SmallSuccess.TButton": colors.success,
            "SmallSecondary.TButton": colors.secondary,
            "SmallDanger.TButton": colors.danger,
        }

        for name, color in definitions.items():
            style.configure(
                name,
                padding=(2, 1),
                background=color,
                foreground="#ffffff",
                bordercolor=color,
                lightcolor=color,
                darkcolor=color,
                focuscolor=color,
                relief="flat",
            )

            style.map(
                name,
                background=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color),
                ],
                foreground=[
                    ("disabled", "#ffffff"),
                    ("pressed", "#ffffff"),
                    ("active", "#ffffff"),
                ],
                bordercolor=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color),
                ],
                lightcolor=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color),
                ],
                darkcolor=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color),
                ],
            )

    def _toggle_theme(self):
        dark_mode = self._theme_switch.instate(["selected"])

        self.root.style.theme_use(
            "darkly" if dark_mode else "flatly"
        )
        self._configure_button_styles()

        for button in self.btns:
            role = getattr(button, "_button_role", None)

            if role in (
                "primary",
                "success",
                "secondary",
                "danger",
            ):
                button.configure(
                    style=f"Small{role.capitalize()}.TButton"
                )
            elif role in (
                "add",
                "unlock",
                "create",
                "generate",
                "edit",
            ):
                button.configure(
                    bootstyle=(
                        "success" if dark_mode else "primary"
                    )
                )
            elif role == "delete":
                button.configure(bootstyle="danger")
            else:
                button.configure(bootstyle="secondary")

    def _set_screen(self, frame):
        if self._frame is not None:
            self._frame.destroy()

        self._frame = frame

        frame.grid(
            column=0,
            row=0,
            padx=20,
            pady=20,
            sticky="nsew",
        )

    def _busy_cursor(self, busy: bool):
        try:
            self.root.config(
                cursor="watch" if busy else ""
            )
            self.root.update_idletasks()
        except tk.TclError:
            pass

    def _center_dialog(self, dialog):
        self.root.update_idletasks()
        dialog.update_idletasks()

        root_x = self.root.winfo_rootx()
        root_y = self.root.winfo_rooty()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()

        dialog_w = dialog.winfo_width()
        dialog_h = dialog.winfo_height()

        x = root_x + (root_w - dialog_w) // 2
        y = root_y + (root_h - dialog_h) // 2

        dialog.geometry(f"+{x}+{y}")

    def _small_button(
        self,
        parent,
        text,
        role,
        command,
        width=None,
    ):
        if width is None:
            width = len(text) + 1

        button = ttk.Button(
            parent,
            text=text,
            width=width,
            padding=(2, 1),
            style=f"Small{role.capitalize()}.TButton",
            command=command,
        )
        button._button_role = role
        return button

    def _show_alert_dialog(self, title, message):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.resizable(False, False)

        dark_mode = self._theme_switch.instate(
            ["selected"]
        )
        bg = "#222222" if dark_mode else "#ffffff"
        fg = "white" if dark_mode else "black"

        dialog.configure(bg=bg)

        body = tk.Frame(
            dialog,
            bg=bg,
        )
        body.pack(
            padx=20,
            pady=18,
        )

        tk.Label(
            body,
            text=message,
            bg=bg,
            fg=fg,
            font=("Segoe UI", 10),
        ).pack(pady=(0, 15))

        ok_btn = self._small_button(
            body,
            "Ok",
            "secondary",
            dialog.destroy,
        )
        ok_btn.pack()

        dialog.update_idletasks()
        self._center_dialog(dialog)
        self._make_modal(dialog)
        self.root.wait_window(dialog)

    def _show_create_screen(self):
        frame = ttk.Frame(
            self.root,
            padding=20,
        )

        ttk.Label(
            frame,
            text="Create Master Password",
            font=("Segoe UI", 14, "bold"),
        ).grid(
            column=0,
            row=0,
            columnspan=2,
            pady=(0, 10),
        )

        ttk.Label(
            frame,
            text=(
                "No vault was found. Choose a master password.\n"
                "It protects all entries and cannot be recovered if lost."
            ),
        ).grid(
            column=0,
            row=1,
            columnspan=2,
            pady=(0, 15),
        )

        ttk.Label(
            frame,
            text="Master Password:",
        ).grid(
            column=0,
            row=2,
            sticky=E,
            padx=(0, 10),
            pady=6,
        )

        self._pw_entry = ttk.Entry(
            frame,
            show="*",
            width=30,
        )
        self._pw_entry.grid(
            column=1,
            row=2,
            sticky=W,
        )

        ttk.Label(
            frame,
            text="Confirm Password:",
        ).grid(
            column=0,
            row=3,
            sticky=E,
            padx=(0, 10),
            pady=6,
        )

        self._confirm_entry = ttk.Entry(
            frame,
            show="*",
            width=30,
        )
        self._confirm_entry.grid(
            column=1,
            row=3,
            sticky=W,
        )

        self.btns = []

        create_btn = ttk.Button(
            frame,
            text="Create Vault",
            bootstyle="primary",
            command=self._on_create_vault,
        )
        create_btn.grid(
            column=0,
            row=4,
            columnspan=2,
            pady=15,
        )
        create_btn._button_role = "create"
        self.btns.append(create_btn)

        self._pw_entry.focus_set()
        self._pw_entry.bind(
            "<Return>",
            lambda _e: self._confirm_entry.focus_set(),
        )
        self._confirm_entry.bind(
            "<Return>",
            lambda _e: self._on_create_vault(),
        )

        self._set_screen(frame)

        if self._theme_switch.instate(["selected"]):
            create_btn.configure(bootstyle="success")

    def _on_create_vault(self):
        pw = self._pw_entry.get()
        confirm = self._confirm_entry.get()

        if not pw:
            self._show_alert_dialog(
                "Error",
                "The master password must not be empty.",
            )
            return

        if pw != confirm:
            self._show_alert_dialog(
                "Error",
                "The passwords do not match.",
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
            self._show_alert_dialog(
                "Error",
                f"Could not create the vault file:\n{exc}",
            )
            return

        self.key = key
        self.salt = salt
        self.entries = []
        self._show_main_screen()

    def _show_unlock_screen(self):
        frame = ttk.Frame(
            self.root,
            padding=20,
        )

        ttk.Label(
            frame,
            text="Unlock Vault",
            font=("Segoe UI", 14, "bold"),
        ).grid(
            column=0,
            row=0,
            columnspan=2,
            pady=(0, 15),
        )

        ttk.Label(
            frame,
            text="Master Password:",
        ).grid(
            column=0,
            row=1,
            sticky=E,
            padx=(0, 10),
            pady=6,
        )

        self._pw_entry = ttk.Entry(
            frame,
            show="*",
            width=30,
        )
        self._pw_entry.grid(
            column=1,
            row=1,
            sticky=W,
        )

        self.btns = []

        unlock_btn = ttk.Button(
            frame,
            text="Unlock",
            bootstyle="primary",
            command=self._on_unlock,
        )
        unlock_btn.grid(
            column=0,
            row=2,
            columnspan=2,
            pady=15,
        )
        unlock_btn._button_role = "unlock"
        self.btns.append(unlock_btn)

        self._pw_entry.focus_set()
        self._pw_entry.bind(
            "<Return>",
            lambda _e: self._on_unlock(),
        )

        self._set_screen(frame)

        if self._theme_switch.instate(["selected"]):
            unlock_btn.configure(bootstyle="success")

    def _on_unlock(self):
        pw = self._pw_entry.get()

        if not pw:
            self._show_alert_dialog(
                "Error",
                "Please enter your master password.",
            )
            return

        try:
            env = load_vault_file()
        except VaultError as exc:
            self._show_alert_dialog(
                "Error",
                str(exc),
            )
            return

        self._busy_cursor(True)
        try:
            key = derive_key(pw, env["salt"])
        finally:
            self._busy_cursor(False)

        try:
            entries = decrypt_entries(
                key,
                env["nonce"],
                env["ciphertext"],
            )
        except InvalidTag:
            self._show_alert_dialog(
                "Error",
                "Incorrect password or corrupted vault file.",
            )
            self._pw_entry.delete(0, tk.END)
            return
        except VaultError as exc:
            self._show_alert_dialog(
                "Error",
                str(exc),
            )
            return

        self.key = key
        self.salt = env["salt"]
        self.entries = entries
        self._show_main_screen()

    def _show_main_screen(self):
        frame = ttk.Frame(
            self.root,
            padding=2,
        )

        ttk.Label(
            frame,
            text="Vault Entries",
            font=("Segoe UI", 12, "bold"),
        ).grid(
            column=0,
            row=0,
            sticky="w",
            columnspan=2,
        )

        list_frame = ttk.Frame(frame)
        list_frame.grid(
            column=0,
            row=1,
            columnspan=2,
            pady=(10, 15),
            sticky="nsew",
        )

        scrollbar = tk.Scrollbar(
            list_frame,
            orient="vertical",
        )

        self.listbox = tk.Listbox(
            list_frame,
            exportselection=False,
            yscrollcommand=scrollbar.set,
            height=10,
            width=70,
        )

        scrollbar.config(
            command=self.listbox.yview
        )
        scrollbar.pack(
            side="right",
            fill="y",
        )
        self.listbox.pack(
            side="left",
            fill="both",
            expand=True,
        )

        self.listbox.bind(
            "<Double-Button-1>",
            lambda _event: self._view_selected(),
        )

        buttons = ttk.Frame(frame)
        buttons.grid(
            column=0,
            row=2,
            columnspan=2,
        )

        self.btns = []

        add_btn = ttk.Button(
            buttons,
            text="Add Entry",
            bootstyle="primary",
            command=self._open_add_dialog,
        )
        add_btn.pack(
            side="left",
            padx=6,
        )
        add_btn._button_role = "add"
        self.btns.append(add_btn)

        view_btn = ttk.Button(
            buttons,
            text="View Entry",
            bootstyle="secondary",
            command=self._view_selected,
        )
        view_btn.pack(
            side="left",
            padx=6,
        )
        view_btn._button_role = "view"
        self.btns.append(view_btn)

        delete_btn = ttk.Button(
            buttons,
            text="Delete Entry",
            bootstyle="danger",
            command=self._delete_selected,
        )
        delete_btn.pack(
            side="left",
            padx=6,
        )
        delete_btn._button_role = "delete"
        self.btns.append(delete_btn)

        self._refresh_listbox()
        self._set_screen(frame)

        if self._theme_switch.instate(["selected"]):
            add_btn.configure(bootstyle="success")

    def _refresh_listbox(self):
        self.listbox.delete(0, tk.END)

        for entry in self.entries:
            self.listbox.insert(
                tk.END,
                entry.get("title", "(untitled)"),
            )

    def _show_no_selection_dialog(self):
        self._show_alert_dialog(
            "No selection",
            "Please select an entry first.",
        )

    def _selected_index(self):
        selection = self.listbox.curselection()

        if not selection:
            self._show_no_selection_dialog()
            return None

        return selection[0]

    def _persist(self) -> bool:
        try:
            save_vault(
                self.entries,
                self.key,
                self.salt,
            )
            return True
        except OSError as exc:
            self._show_alert_dialog(
                "Save failed",
                f"Could not write the vault file:\n{exc}",
            )
            return False

    @staticmethod
    def _toggle_show(entry, button):
        if entry.cget("show"):
            entry.config(show="")
            button.config(
                text="Hide",
                width=SHOW_BUTTON_WIDTH,
            )
        else:
            entry.config(show="*")
            button.config(
                text="Show",
                width=SHOW_BUTTON_WIDTH,
            )

    @staticmethod
    def _make_modal(dialog):
        try:
            dialog.wait_visibility()
            dialog.grab_set()
        except tk.TclError:
            pass

    def _generate_password_into(self, entry):
        password = generate_password()
        current_state = entry.cget("state")

        if current_state == "readonly":
            entry.config(state="normal")

        entry.delete(0, tk.END)
        entry.insert(0, password)

        if current_state == "readonly":
            entry.config(state="readonly")

    def _open_add_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Entry")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        body = tk.Frame(dialog)
        body.pack(
            padx=14,
            pady=14,
        )

        tk.Label(
            body,
            text="Title:",
        ).grid(
            row=0,
            column=0,
            sticky="e",
            pady=2,
        )

        self._add_title = tk.Entry(
            body,
            width=30,
        )
        self._add_title.grid(
            row=0,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        tk.Label(
            body,
            text="Username:",
        ).grid(
            row=1,
            column=0,
            sticky="e",
            pady=2,
        )

        self._add_username = tk.Entry(
            body,
            width=30,
        )
        self._add_username.grid(
            row=1,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        tk.Label(
            body,
            text="Password:",
        ).grid(
            row=2,
            column=0,
            sticky="e",
            pady=2,
        )

        password_row = tk.Frame(body)
        password_row.grid(
            row=2,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        self._add_password = tk.Entry(
            password_row,
            width=PASSWORD_FIELD_WIDTH,
            show="*",
        )
        self._add_password.pack(side="left")

        toggle_btn = self._small_button(
            password_row,
            "Show",
            "secondary",
            lambda: self._toggle_show(
                self._add_password,
                toggle_btn,
            ),
            width=SHOW_BUTTON_WIDTH,
        )
        toggle_btn.pack(
            side="left",
            padx=(6, 0),
        )

        dark_mode = self._theme_switch.instate(["selected"])

        generate_btn = self._small_button(
            password_row,
            "Generate",
            "generate",
            lambda: self._generate_password_into(
                self._add_password
            ),
            width=GENERATE_BUTTON_WIDTH,
        )
        generate_btn.configure(
            bootstyle=(
                "success" if dark_mode else "primary"
            )
        )
        generate_btn.pack(
            side="left",
            padx=(6, 0),
        )

        tk.Label(
            body,
            text="Notes:",
        ).grid(
            row=4,
            column=0,
            sticky="ne",
            pady=2,
        )

        self._add_notes = tk.Text(
            body,
            width=30,
            height=5,
        )
        self._add_notes.grid(
            row=4,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        btns = tk.Frame(dialog)
        btns.pack(pady=(0, 12))

        save_btn = self._small_button(
            btns,
            "Save",
            "success" if dark_mode else "primary",
            self._on_add_save,
        )
        save_btn.pack(
            side="left",
            padx=5,
        )

        cancel_btn = self._small_button(
            btns,
            "Cancel",
            "secondary",
            dialog.destroy,
        )
        cancel_btn.pack(
            side="left",
            padx=5,
        )

        self._add_dialog = dialog

        self._add_title.focus_set()

        dialog.update_idletasks()
        self._center_dialog(dialog)
        self._make_modal(dialog)

    def _on_add_save(self):
        title = self._add_title.get().strip()

        if not title:
            self._show_alert_dialog(
                "Error",
                "Title must not be empty.",
            )
            return

        entry = {
            "id": str(uuid.uuid4()),
            "title": title,
            "username": self._add_username.get(),
            "password": self._add_password.get(),
            "notes": self._add_notes.get(
                "1.0",
                "end-1c",
            ),
            "created": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        self.entries.append(entry)

        if not self._persist():
            self.entries.pop()
            return

        self._refresh_listbox()
        self._add_dialog.destroy()

    def _view_selected(self):
        index = self._selected_index()

        if index is None:
            return

        self._open_entry_dialog(index)

    def _open_entry_dialog(self, index):
        entry = self.entries[index]

        dialog = tk.Toplevel(self.root)
        dialog.withdraw()
        dialog.title(
            f"View Entry - {entry.get('title', '')}"
        )
        dialog.transient(self.root)
        dialog.resizable(False, False)

        dark_mode = self._theme_switch.instate(
            ["selected"]
        )
        bg = "#1f1f1f" if dark_mode else "white"
        fg = "white" if dark_mode else "black"

        dialog.configure(bg=bg)

        # Smaller fixed body keeps the View/Edit dialog compact.
        BODY_WIDTH = 390
        BODY_HEIGHT = 212

        body = tk.Frame(
            dialog,
            bg=bg,
            width=BODY_WIDTH,
            height=BODY_HEIGHT,
        )
        body.pack(
            padx=12,
            pady=12,
        )
        body.pack_propagate(False)

        body.grid_columnconfigure(
            0,
            minsize=72,
            weight=0,
        )
        body.grid_columnconfigure(
            1,
            minsize=155,
            weight=0,
        )
        body.grid_columnconfigure(
            2,
            minsize=58,
            weight=0,
        )
        body.grid_columnconfigure(
            3,
            minsize=0,
            weight=0,
        )

        tk.Label(
            body,
            text="Title:",
            bg=bg,
            fg=fg,
        ).grid(
            row=0,
            column=0,
            sticky="e",
            pady=2,
        )

        title_field = tk.Entry(
            body,
            width=30,
            bg=bg,
            fg=fg,
            insertbackground=fg,
            readonlybackground=bg,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#555555",
            highlightcolor="#777777",
        )
        title_field.insert(
            0,
            entry.get("title", ""),
        )
        title_field.config(state="readonly")
        title_field.grid(
            row=0,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        tk.Label(
            body,
            text="Username:",
            bg=bg,
            fg=fg,
        ).grid(
            row=1,
            column=0,
            sticky="e",
            pady=2,
        )

        username_field = tk.Entry(
            body,
            width=30,
            bg=bg,
            fg=fg,
            insertbackground=fg,
            readonlybackground=bg,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#555555",
            highlightcolor="#777777",
        )
        username_field.insert(
            0,
            entry.get("username", ""),
        )
        username_field.config(state="readonly")
        username_field.grid(
            row=1,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        tk.Label(
            body,
            text="Password:",
            bg=bg,
            fg=fg,
        ).grid(
            row=2,
            column=0,
            sticky="e",
            pady=2,
        )

        password_row = tk.Frame(
            body,
            bg=bg,
        )
        password_row.grid(
            row=2,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        password_field = tk.Entry(
            password_row,
            width=PASSWORD_FIELD_WIDTH,
            bg=bg,
            fg=fg,
            insertbackground=fg,
            readonlybackground=bg,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#555555",
            highlightcolor="#777777",
            show="*",
        )
        password_field.insert(
            0,
            entry.get("password", ""),
        )
        password_field.config(state="readonly")
        password_field.pack(side="left")

        password_toggle = self._small_button(
            password_row,
            "Show",
            "secondary",
            lambda: self._toggle_show(
                password_field,
                password_toggle,
            ),
            width=SHOW_BUTTON_WIDTH,
        )
        password_toggle.pack(
            side="left",
            padx=(6, 0),
        )

        generate_slot = tk.Frame(
            password_row,
            bg=bg,
            width=GENERATE_BUTTON_WIDTH * 8,
            height=28,
        )
        generate_slot.pack(
            side="left",
            padx=(6, 0),
        )
        generate_slot.pack_propagate(False)

        generate_btn = self._small_button(
            generate_slot,
            "Generate",
            "generate",
            lambda: self._generate_password_into(
                password_field
            ),
            width=GENERATE_BUTTON_WIDTH,
        )
        generate_btn.configure(
            bootstyle=(
                "success" if dark_mode else "primary"
            )
        )
        generate_btn.pack(
            fill="x",
            expand=True,
        )
        generate_btn.pack_forget()

        tk.Label(
            body,
            text="Notes:",
            bg=bg,
            fg=fg,
        ).grid(
            row=4,
            column=0,
            sticky="ne",
            pady=2,
        )

        notes = tk.Text(
            body,
            width=30,
            height=5,
            bg=bg,
            fg=fg,
            insertbackground=fg,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#555555",
            highlightcolor="#777777",
        )
        notes.insert(
            "1.0",
            entry.get("notes", ""),
        )
        notes.config(state="disabled")
        notes.grid(
            row=4,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        tk.Label(
            body,
            text="Created:",
            bg=bg,
            fg=fg,
        ).grid(
            row=5,
            column=0,
            sticky="e",
            pady=2,
        )

        created_field = tk.Entry(
            body,
            width=34,
            bg=bg,
            fg=fg,
            insertbackground=fg,
            readonlybackground=bg,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#555555",
            highlightcolor="#777777",
        )
        created_field.insert(
            0,
            entry.get("created", ""),
        )
        created_field.config(state="readonly")
        created_field.grid(
            row=5,
            column=1,
            columnspan=3,
            sticky="w",
            pady=2,
        )

        ACTION_WIDTH = BODY_WIDTH
        ACTION_HEIGHT = 34

        action_frame = tk.Frame(
            dialog,
            width=ACTION_WIDTH,
            height=ACTION_HEIGHT,
            bg=bg,
        )
        action_frame.pack(
            padx=12,
            pady=(2, 10),
        )
        action_frame.pack_propagate(False)

        edit_btn = self._small_button(
            action_frame,
            "Edit",
            "edit",
            lambda: enter_edit_mode(),
            width=7,
        )
        edit_btn.configure(
            bootstyle=(
                "success" if dark_mode else "primary"
            )
        )

        close_btn = self._small_button(
            action_frame,
            "Close",
            "secondary",
            dialog.destroy,
            width=8,
        )

        save_btn = self._small_button(
            action_frame,
            "Save",
            "success" if dark_mode else "primary",
            lambda: save_edit(),
            width=7,
        )

        cancel_btn = self._small_button(
            action_frame,
            "Cancel",
            "secondary",
            lambda: cancel_edit(),
            width=9,
        )

        button_gap = 8
        center_y = 2

        edit_width = edit_btn.winfo_reqwidth()
        edit_height = edit_btn.winfo_reqheight()
        close_width = close_btn.winfo_reqwidth()
        close_height = close_btn.winfo_reqheight()
        save_width = save_btn.winfo_reqwidth()
        save_height = save_btn.winfo_reqheight()
        cancel_width = cancel_btn.winfo_reqwidth()
        cancel_height = cancel_btn.winfo_reqheight()

        centered_group_width = (
            edit_width
            + button_gap
            + close_width
        )
        centered_start_x = (
            ACTION_WIDTH - centered_group_width
        ) // 2

        edit_btn.place(
            x=centered_start_x,
            y=center_y,
            width=edit_width,
            height=edit_height,
        )
        close_btn.place(
            x=centered_start_x
            + edit_width
            + button_gap,
            y=center_y,
            width=close_width,
            height=close_height,
        )

        save_btn.place(
            x=0,
            y=center_y,
            width=save_width,
            height=save_height,
        )
        cancel_btn.place(
            x=save_width + button_gap,
            y=center_y,
            width=cancel_width,
            height=cancel_height,
        )

        save_btn.place_forget()
        cancel_btn.place_forget()

        def set_field_editable(field, editable):
            if isinstance(field, tk.Text):
                field.config(
                    state=(
                        "normal"
                        if editable
                        else "disabled"
                    )
                )
                return

            field.config(
                state=(
                    "normal"
                    if editable
                    else "readonly"
                )
            )

        def enter_edit_mode():
            for field in (
                title_field,
                username_field,
                password_field,
                notes,
            ):
                set_field_editable(field, True)

            generate_btn.pack(
                fill="x",
                expand=True,
            )

            edit_btn.place_forget()
            close_btn.place_forget()

            save_btn.place(
                x=0,
                y=center_y,
                width=save_width,
                height=save_height,
            )
            cancel_btn.place(
                x=save_width + button_gap,
                y=center_y,
                width=cancel_width,
                height=cancel_height,
            )

            title_field.focus_set()

        def cancel_edit():
            title_field.config(state="normal")
            title_field.delete(0, tk.END)
            title_field.insert(
                0,
                entry.get("title", ""),
            )
            title_field.config(state="readonly")

            username_field.config(state="normal")
            username_field.delete(0, tk.END)
            username_field.insert(
                0,
                entry.get("username", ""),
            )
            username_field.config(state="readonly")

            password_field.config(state="normal")
            password_field.delete(0, tk.END)
            password_field.insert(
                0,
                entry.get("password", ""),
            )
            password_field.config(state="readonly")

            notes.config(state="normal")
            notes.delete("1.0", tk.END)
            notes.insert(
                "1.0",
                entry.get("notes", ""),
            )
            notes.config(state="disabled")

            generate_btn.pack_forget()
            save_btn.place_forget()
            cancel_btn.place_forget()

            edit_btn.place(
                x=centered_start_x,
                y=center_y,
                width=edit_width,
                height=edit_height,
            )
            close_btn.place(
                x=(
                    centered_start_x
                    + edit_width
                    + button_gap
                ),
                y=center_y,
                width=close_width,
                height=close_height,
            )

        def save_edit():
            title = title_field.get().strip()

            if not title:
                self._show_alert_dialog(
                    "Error",
                    "Title must not be empty.",
                )
                return

            updated_entry = entry.copy()
            updated_entry["title"] = title
            updated_entry["username"] = (
                username_field.get()
            )
            updated_entry["password"] = (
                password_field.get()
            )
            updated_entry["notes"] = notes.get(
                "1.0",
                "end-1c",
            )

            original_entry = self.entries[index]
            self.entries[index] = updated_entry

            if not self._persist():
                self.entries[index] = original_entry
                return

            self._refresh_listbox()

            entry.clear()
            entry.update(updated_entry)

            dialog.title(
                f"View Entry - "
                f"{entry.get('title', '')}"
            )

            set_field_editable(
                title_field,
                False,
            )
            set_field_editable(
                username_field,
                False,
            )
            set_field_editable(
                password_field,
                False,
            )
            set_field_editable(
                notes,
                False,
            )

            generate_btn.pack_forget()
            save_btn.place_forget()
            cancel_btn.place_forget()

            edit_btn.place(
                x=centered_start_x,
                y=center_y,
                width=edit_width,
                height=edit_height,
            )
            close_btn.place(
                x=(
                    centered_start_x
                    + edit_width
                    + button_gap
                ),
                y=center_y,
                width=close_width,
                height=close_height,
            )

        dialog.update_idletasks()

        fixed_width = BODY_WIDTH + 24
        fixed_height = dialog.winfo_reqheight()

        dialog.geometry(
            f"{fixed_width}x{fixed_height}"
        )
        dialog.minsize(
            fixed_width,
            fixed_height,
        )
        dialog.maxsize(
            fixed_width,
            fixed_height,
        )

        self._center_dialog(dialog)
        dialog.update_idletasks()
        self._center_dialog(dialog)

        dialog.deiconify()
        dialog.lift()
        self._make_modal(dialog)

    def _confirm_delete(self, title):
        dialog = tk.Toplevel(self.root)
        dialog.title("Confirm Delete")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        dark_mode = self._theme_switch.instate(
            ["selected"]
        )
        bg = "#222222" if dark_mode else "#ffffff"
        fg = "white" if dark_mode else "black"

        dialog.configure(bg=bg)

        body = tk.Frame(
            dialog,
            bg=bg,
        )
        body.pack(
            padx=20,
            pady=18,
        )

        tk.Label(
            body,
            text=f"Delete '{title}'?",
            bg=bg,
            fg=fg,
            font=("Segoe UI", 10, "bold"),
        ).pack(pady=(0, 8))

        tk.Label(
            body,
            text="This cannot be undone.",
            bg=bg,
            fg=fg,
        ).pack(pady=(0, 15))

        button_frame = tk.Frame(
            body,
            bg=bg,
        )
        button_frame.pack()

        result = {"confirmed": False}

        def confirm():
            result["confirmed"] = True
            dialog.destroy()

        def cancel():
            dialog.destroy()

        delete_btn = self._small_button(
            button_frame,
            "Delete",
            "success" if dark_mode else "primary",
            confirm,
        )
        delete_btn.pack(
            side="left",
            padx=5,
        )

        cancel_btn = self._small_button(
            button_frame,
            "Cancel",
            "secondary",
            cancel,
        )
        cancel_btn.pack(
            side="left",
            padx=5,
        )

        dialog.update_idletasks()
        self._center_dialog(dialog)
        self._make_modal(dialog)
        self.root.wait_window(dialog)

        return result["confirmed"]

    def _delete_selected(self):
        index = self._selected_index()

        if index is None:
            return

        title = self.entries[index].get(
            "title",
            "(untitled)",
        )

        if not self._confirm_delete(title):
            return

        removed = self.entries.pop(index)

        if not self._persist():
            self.entries.insert(index, removed)
            return

        self._refresh_listbox()

    def _lock_and_exit(self):
        self.key = None
        self.entries = []
        self.root.destroy()


def main():
    root = ttk.Window(themename="flatly")
    PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
