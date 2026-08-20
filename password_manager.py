import base64
import json
import os
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
    os.path.dirname(os.path.abspath(__file__)), "vault.enc"
)
KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536
KDF_PARALLELISM = 4
KDF_HASH_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16
VAULT_VERSION = 1


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
        type=Type.ID
    )


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
            "parallelism": KDF_PARALLELISM
        },
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii")
    }
    tmp_path = VAULT_PATH + ".tmp"
    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600
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
        raise VaultError(f"Could not read the vault file:\n{exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultError(
            "The vault file is not valid JSON (corrupted?)."
        ) from exc
    if not isinstance(data, dict):
        raise VaultError(
            "The vault file is malformed (expected a JSON object)."
        )
    if data.get("version") != VAULT_VERSION or data.get("kdf") != "argon2id":
        raise VaultError("The vault file has an unsupported version or KDF.")
    decoded = {}
    for field, expected_len in (
        ("salt", SALT_LEN),
        ("nonce", NONCE_LEN),
        ("ciphertext", None)
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
        raise VaultError("The vault file ciphertext is too short.")
    return decoded


def decrypt_entries(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes
) -> list:
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
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
            command=self._toggle_theme
        )
        self._theme_switch.grid(
            column=1,
            row=99,
            sticky="e",
            padx=10,
            pady=10
        )

        bottom_frame = ttk.Frame(self.root)
        bottom_frame.grid(
            row=99,
            column=0,
            sticky="sw",
            padx=1,
            pady=1
        )
        ttk.Label(
            bottom_frame,
            text="© 2026 Stevan Stefanovic",
            font=("Segoe UI", 8, "bold")
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
            "SmallDanger.TButton": colors.danger
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
                relief="flat"
            )
            style.map(
                name,
                background=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color)
                ],
                foreground=[
                    ("disabled", "#ffffff"),
                    ("pressed", "#ffffff"),
                    ("active", "#ffffff")
                ],
                bordercolor=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color)
                ],
                lightcolor=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color)
                ],
                darkcolor=[
                    ("disabled", color),
                    ("pressed", color),
                    ("active", color)
                ]
            )

    def _toggle_theme(self):
        dark_mode = self._theme_switch.instate(["selected"])
        self.root.style.theme_use("darkly" if dark_mode else "flatly")
        self._configure_button_styles()

        for button in self.btns:
            role = getattr(button, "_button_role", None)
            if role in ("primary", "success", "secondary", "danger"):
                button.configure(
                    style=f"Small{role.capitalize()}.TButton"
                )
            elif role in ("add", "unlock", "create"):
                button.configure(
                    bootstyle="success" if dark_mode else "primary"
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
            sticky="nsew"
        )

    def _busy_cursor(self, busy: bool):
        try:
            self.root.config(cursor="watch" if busy else "")
            self.root.update_idletasks()
        except tk.TclError:
            pass

    def _center_dialog(self, dialog):
        self.root.update_idletasks()
        dialog.update_idletasks()
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        dialog_w = dialog.winfo_width()
        dialog_h = dialog.winfo_height()
        x = root_x + (root_w - dialog_w) // 2
        y = root_y + (root_h - dialog_h) // 2
        dialog.geometry(f"+{x}+{y}")

    def _small_button(self, parent, text, role, command):
        button = ttk.Button(
            parent,
            text=text,
            width=len(text) + 1,
            style=f"Small{role.capitalize()}.TButton",
            command=command
        )
        button._button_role = role
        return button

    def _show_alert_dialog(self, title, message):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.resizable(False, False)

        dark_mode = self._theme_switch.instate(["selected"])
        bg = "#222222" if dark_mode else "#ffffff"
        fg = "white" if dark_mode else "black"
        dialog.configure(bg=bg)

        body = tk.Frame(dialog, bg=bg)
        body.pack(padx=20, pady=18)

        tk.Label(
            body,
            text=message,
            bg=bg,
            fg=fg,
            font=("Segoe UI", 9)
        ).pack(pady=(0, 15))

        ok_btn = self._small_button(
            body,
            "Ok",
            "secondary",
            dialog.destroy
        )
        ok_btn.pack()

        dialog.update_idletasks()
        self._center_dialog(dialog)
        self._make_modal(dialog)
        self.root.wait_window(dialog)

    def _show_create_screen(self):
        frame = ttk.Frame(self.root, padding=20)

        ttk.Label(
            frame,
            text="Create Master Password",
            font=("Segoe UI", 14, "bold")
        ).grid(
            column=0,
            row=0,
            columnspan=2,
            pady=(0, 10)
        )

        ttk.Label(
            frame,
            text="No vault was found. Choose a master password.\n"
                 "It protects all entries and cannot be recovered if lost."
        ).grid(
            column=0,
            row=1,
            columnspan=2,
            pady=(0, 15)
        )

        ttk.Label(frame, text="Master Password:").grid(
            column=0,
            row=2,
            sticky=E,
            padx=(0, 10),
            pady=6
        )

        self._pw_entry = ttk.Entry(frame, show="*", width=30)
        self._pw_entry.grid(column=1, row=2, sticky=W)

        ttk.Label(frame, text="Confirm Password:").grid(
            column=0,
            row=3,
            sticky=E,
            padx=(0, 10),
            pady=6
        )

        self._confirm_entry = ttk.Entry(frame, show="*", width=30)
        self._confirm_entry.grid(column=1, row=3, sticky=W)

        self.btns = []

        create_btn = ttk.Button(
            frame,
            text="Create Vault",
            bootstyle="primary",
            command=self._on_create_vault
        )
        create_btn.grid(
            column=0,
            row=4,
            columnspan=2,
            pady=15
        )
        create_btn._button_role = "create"
        self.btns.append(create_btn)

        self._pw_entry.focus_set()
        self._pw_entry.bind(
            "<Return>",
            lambda _e: self._confirm_entry.focus_set()
        )
        self._confirm_entry.bind(
            "<Return>",
            lambda _e: self._on_create_vault()
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
                "The master password must not be empty."
            )
            return

        if pw != confirm:
            self._show_alert_dialog(
                "Error",
                "The passwords do not match."
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
                "Error",
                f"Could not create the vault file:\n{exc}",
                parent=self.root
            )
            return

        self.key = key
        self.salt = salt
        self.entries = []
        self._show_main_screen()

    def _show_unlock_screen(self):
        frame = ttk.Frame(self.root, padding=20)

        ttk.Label(
            frame,
            text="Unlock Vault",
            font=("Segoe UI", 14, "bold")
        ).grid(
            column=0,
            row=0,
            columnspan=2,
            pady=(0, 15)
        )

        ttk.Label(frame, text="Master Password:").grid(
            column=0,
            row=1,
            sticky=E,
            padx=(0, 10),
            pady=6
        )

        self._pw_entry = ttk.Entry(frame, show="*", width=30)
        self._pw_entry.grid(column=1, row=1, sticky=W)

        self.btns = []

        unlock_btn = ttk.Button(
            frame,
            text="Unlock",
            bootstyle="primary",
            command=self._on_unlock
        )
        unlock_btn.grid(
            column=0,
            row=2,
            columnspan=2,
            pady=15
        )
        unlock_btn._button_role = "unlock"
        self.btns.append(unlock_btn)

        self._pw_entry.focus_set()
        self._pw_entry.bind(
            "<Return>",
            lambda _e: self._on_unlock()
        )

        self._set_screen(frame)

        if self._theme_switch.instate(["selected"]):
            unlock_btn.configure(bootstyle="success")

    def _on_unlock(self):
        pw = self._pw_entry.get()

        if not pw:
            self._show_alert_dialog(
                "Error",
                "Please enter your master password."
            )
            return

        try:
            env = load_vault_file()
        except VaultError as exc:
            self._show_alert_dialog("Error", str(exc))
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
                env["ciphertext"]
            )
        except InvalidTag:
            self._show_alert_dialog(
                "Error",
                "Incorrect password or corrupted vault file."
            )
            self._pw_entry.delete(0, tk.END)
            return
        except VaultError as exc:
            self._show_alert_dialog("Error", str(exc))
            return

        self.key = key
        self.salt = env["salt"]
        self.entries = entries
        self._show_main_screen()

    def _show_main_screen(self):
        frame = ttk.Frame(self.root, padding=2)

        ttk.Label(
            frame,
            text="Vault Entries",
            font=("Segoe UI", 12, "bold")
        ).grid(
            column=0,
            row=0,
            sticky="w",
            columnspan=2
        )

        list_frame = ttk.Frame(frame)
        list_frame.grid(
            column=0,
            row=1,
            columnspan=2,
            pady=(10, 15),
            sticky="nsew"
        )

        scrollbar = tk.Scrollbar(list_frame, orient="vertical")
        self.listbox = tk.Listbox(
            list_frame,
            exportselection=False,
            yscrollcommand=scrollbar.set,
            height=10,
            width=70
        )

        scrollbar.config(command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind(
            "<Double-Button-1>",
            lambda _event: self._view_selected()
        )

        buttons = ttk.Frame(frame)
        buttons.grid(
            column=0,
            row=2,
            columnspan=2
        )

        self.btns = []

        add_btn = ttk.Button(
            buttons,
            text="Add Entry",
            bootstyle="primary",
            command=self._open_add_dialog
        )
        add_btn.pack(side="left", padx=6)
        add_btn._button_role = "add"
        self.btns.append(add_btn)

        view_btn = ttk.Button(
            buttons,
            text="View Entry",
            bootstyle="secondary",
            command=self._view_selected
        )
        view_btn.pack(side="left", padx=6)
        view_btn._button_role = "view"
        self.btns.append(view_btn)

        delete_btn = ttk.Button(
            buttons,
            text="Delete Entry",
            bootstyle="danger",
            command=self._delete_selected
        )
        delete_btn.pack(side="left", padx=6)
        delete_btn._button_role = "delete"
        self.btns.append(delete_btn)

        lock_btn = ttk.Button(
            buttons,
            text="Lock/Exit",
            bootstyle="secondary",
            command=self._lock_and_exit
        )
        lock_btn.pack(side="left", padx=6)
        lock_btn._button_role = "lock"
        self.btns.append(lock_btn)

        self._refresh_listbox()
        self._set_screen(frame)

        if self._theme_switch.instate(["selected"]):
            add_btn.configure(bootstyle="success")

    def _refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        for entry in self.entries:
            self.listbox.insert(
                tk.END,
                entry.get("title", "(untitled)")
            )

    def _show_no_selection_dialog(self):
        self._show_alert_dialog(
            "No selection",
            "Please select an entry first."
        )

    def _selected_index(self):
        selection = self.listbox.curselection()
        if not selection:
            self._show_no_selection_dialog()
            return None
        return selection[0]

    def _persist(self) -> bool:
        try:
            save_vault(self.entries, self.key, self.salt)
            return True
        except OSError as exc:
            messagebox.showerror(
                "Save failed",
                f"Could not write the vault file:\n{exc}",
                parent=self.root
            )
            return False

    @staticmethod
    def _toggle_show(entry, button):
        if entry.cget("show"):
            entry.config(show="")
            button.config(text="Hide", width=len("Hide") + 1)
        else:
            entry.config(show="*")
            button.config(text="Show", width=len("Show") + 1)

    @staticmethod
    def _make_modal(dialog):
        try:
            dialog.wait_visibility()
            dialog.grab_set()
        except tk.TclError:
            pass

    def _open_add_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Entry")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        body = tk.Frame(dialog)
        body.pack(padx=16, pady=16)

        tk.Label(body, text="Title:").grid(
            row=0,
            column=0,
            sticky="e",
            pady=2
        )

        self._add_title = tk.Entry(body, width=32)
        self._add_title.grid(
            row=0,
            column=1,
            columnspan=2,
            sticky="w",
            pady=2
        )

        tk.Label(body, text="Username:").grid(
            row=1,
            column=0,
            sticky="e",
            pady=2
        )

        self._add_username = tk.Entry(body, width=32)
        self._add_username.grid(
            row=1,
            column=1,
            columnspan=2,
            sticky="w",
            pady=2
        )

        tk.Label(body, text="Password:").grid(
            row=2,
            column=0,
            sticky="e",
            pady=2
        )

        self._add_password = tk.Entry(
            body,
            width=24,
            show="*"
        )
        self._add_password.grid(
            row=2,
            column=1,
            sticky="w",
            pady=2
        )

        toggle_btn = self._small_button(
            body,
            "Show",
            "secondary",
            lambda: self._toggle_show(
                self._add_password,
                toggle_btn
            )
        )
        toggle_btn.grid(
            row=2,
            column=2,
            sticky="w",
            padx=(6, 0),
            pady=2
        )

        tk.Label(body, text="Notes:").grid(
            row=3,
            column=0,
            sticky="ne",
            pady=2
        )

        self._add_notes = tk.Text(
            body,
            width=32,
            height=5
        )
        self._add_notes.grid(
            row=3,
            column=1,
            columnspan=2,
            sticky="w",
            pady=2
        )

        btns = tk.Frame(dialog)
        btns.pack(pady=(0, 12))

        save_btn = self._small_button(
            btns,
            "Save",
            "success"
            if self._theme_switch.instate(["selected"])
            else "primary",
            self._on_add_save
        )
        save_btn.pack(side="left", padx=5)

        cancel_btn = self._small_button(
            btns,
            "Cancel",
            "secondary",
            dialog.destroy
        )
        cancel_btn.pack(side="left", padx=5)

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
                "Title must not be empty."
            )
            return

        entry = {
            "id": str(uuid.uuid4()),
            "title": title,
            "username": self._add_username.get(),
            "password": self._add_password.get(),
            "notes": self._add_notes.get("1.0", "end-1c"),
            "created": datetime.now(timezone.utc).isoformat()
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

        entry = self.entries[index]
        dialog = tk.Toplevel(self.root)
        dialog.title(f"View Entry - {entry.get('title', '')}")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        dark_mode = self._theme_switch.instate(["selected"])
        bg = "#1f1f1f" if dark_mode else "white"
        fg = "white" if dark_mode else "black"

        body = tk.Frame(dialog, bg=bg)
        body.pack(padx=16, pady=16)

        def readonly_row(row, label, value, masked=False):
            tk.Label(
                body,
                text=label,
                bg=bg,
                fg=fg
            ).grid(
                row=row,
                column=0,
                sticky="e",
                pady=2
            )

            field = tk.Entry(
                body,
                width=24 if masked else 32,
                bg=bg,
                fg=fg,
                insertbackground=fg,
                readonlybackground=bg,
                relief="solid",
                highlightthickness=1,
                highlightbackground="#555555",
                highlightcolor="#777777"
            )
            field.insert(0, value)

            if masked:
                field.config(show="*")

            field.config(state="readonly")
            field.grid(
                row=row,
                column=1,
                columnspan=1 if masked else 2,
                sticky="w",
                pady=2
            )
            return field

        readonly_row(0, "Title:", entry.get("title", ""))
        readonly_row(1, "Username:", entry.get("username", ""))

        pw_field = readonly_row(
            2,
            "Password:",
            entry.get("password", ""),
            masked=True
        )

        toggle_btn = self._small_button(
            body,
            "Show",
            "secondary",
            lambda: self._toggle_show(
                pw_field,
                toggle_btn
            )
        )
        toggle_btn.grid(
            row=2,
            column=2,
            sticky="w",
            padx=(6, 0),
            pady=2
        )

        tk.Label(
            body,
            text="Notes:",
            bg=bg,
            fg=fg
        ).grid(
            row=3,
            column=0,
            sticky="ne",
            pady=2
        )

        notes = tk.Text(
            body,
            width=32,
            height=5,
            bg=bg,
            fg=fg,
            insertbackground=fg,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#555555",
            highlightcolor="#777777"
        )
        notes.insert("1.0", entry.get("notes", ""))
        notes.config(state="disabled")
        notes.grid(
            row=3,
            column=1,
            columnspan=2,
            sticky="w",
            pady=2
        )

        readonly_row(4, "Created:", entry.get("created", ""))

        close_btn = self._small_button(
            dialog,
            "Close",
            "secondary",
            dialog.destroy
        )
        close_btn.pack(pady=(0, 12))

        dialog.update_idletasks()
        self._center_dialog(dialog)
        self._make_modal(dialog)

    def _confirm_delete(self, title):
        dialog = tk.Toplevel(self.root)
        dialog.title("Confirm Delete")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        dark_mode = self._theme_switch.instate(["selected"])
        bg = "#222222" if dark_mode else "#ffffff"
        fg = "white" if dark_mode else "black"
        dialog.configure(bg=bg)

        body = tk.Frame(dialog, bg=bg)
        body.pack(padx=20, pady=18)

        tk.Label(
            body,
            text=f"Delete '{title}'?",
            bg=bg,
            fg=fg,
            font=("Segoe UI", 10, "bold")
        ).pack(pady=(0, 8))

        tk.Label(
            body,
            text="This cannot be undone.",
            bg=bg,
            fg=fg
        ).pack(pady=(0, 15))

        button_frame = tk.Frame(body, bg=bg)
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
            confirm
        )
        delete_btn.pack(side="left", padx=5)

        cancel_btn = self._small_button(
            button_frame,
            "Cancel",
            "secondary",
            cancel
        )
        cancel_btn.pack(side="left", padx=5)

        dialog.update_idletasks()
        self._center_dialog(dialog)
        self._make_modal(dialog)
        self.root.wait_window(dialog)

        return result["confirmed"]

    def _delete_selected(self):
        index = self._selected_index()
        if index is None:
            return

        title = self.entries[index].get("title", "(untitled)")

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