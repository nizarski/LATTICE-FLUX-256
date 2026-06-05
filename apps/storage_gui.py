#!/usr/bin/env python3
"""
LF-256 Storage Vault GUI - generate map, import map/keys, passphrase seal/unseal.

  python apps/storage_gui.py
"""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from bootstrap import ensure_src

ensure_src()

from lf256 import AeadDecryptError, KEMDecapsulationError, LF256KeyMap


class LF256StorageVaultGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("LF-256 Storage Vault - Map / Keys / Passphrase")
        self.root.geometry("720x580")
        self.root.minsize(680, 520)

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"), foreground="#2c3e50")
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", font=("Consolas", 9), foreground="#7f8c8d")

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding="15")
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main,
            text="LF-256 STORAGE VAULT - Separated Map, Keys & Passphrase",
            style="Header.TLabel",
        ).pack(anchor=tk.W, pady=(0, 12))

        # --- 1. Key map ---
        map_lf = ttk.LabelFrame(main, text=" 1. Key Map (import or generate) ", padding="10")
        map_lf.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(map_lf, text="Map file (.lf256.map.json):").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.map_path = tk.StringVar()
        ttk.Entry(map_lf, textvariable=self.map_path, width=52).grid(row=0, column=1, padx=5, pady=4)
        ttk.Button(map_lf, text="Browse…", command=self._browse_map).grid(row=0, column=2, pady=4)
        ttk.Button(map_lf, text="Generate Key Map", style="Accent.TButton", command=self._generate_map_thread).grid(
            row=1, column=1, sticky=tk.E, padx=5, pady=6
        )

        # --- 2. Keys + ciphertext paths ---
        files_lf = ttk.LabelFrame(main, text=" 2. Keys & ciphertext paths ", padding="10")
        files_lf.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(files_lf, text="Keys file (.lf256.keys.json):").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.keys_path = tk.StringVar()
        ttk.Entry(files_lf, textvariable=self.keys_path, width=52).grid(row=0, column=1, padx=5, pady=4)
        ttk.Button(files_lf, text="Browse…", command=self._browse_keys).grid(row=0, column=2, pady=4)

        ttk.Label(files_lf, text="Ciphertext (.lf256.enc):").grid(row=1, column=0, sticky=tk.W, pady=4)
        self.enc_path = tk.StringVar()
        ttk.Entry(files_lf, textvariable=self.enc_path, width=52).grid(row=1, column=1, padx=5, pady=4)
        ttk.Button(files_lf, text="Browse…", command=self._browse_enc).grid(row=1, column=2, pady=4)

        ttk.Label(files_lf, text="Plaintext input (encrypt):").grid(row=2, column=0, sticky=tk.W, pady=4)
        self.plain_path = tk.StringVar()
        ttk.Entry(files_lf, textvariable=self.plain_path, width=52).grid(row=2, column=1, padx=5, pady=4)
        ttk.Button(files_lf, text="Browse…", command=self._browse_plain).grid(row=2, column=2, pady=4)

        # --- 3. Passphrase (manual only) ---
        pass_lf = ttk.LabelFrame(
            main,
            text=" 3. Passphrase (never written to map/keys - enter manually) ",
            padding="10",
        )
        pass_lf.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(pass_lf, text="Passphrase:").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.passphrase_entry = ttk.Entry(pass_lf, width=40, show="•")
        self.passphrase_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=4)

        ttk.Label(pass_lf, text="Confirm (encrypt only):").grid(row=1, column=0, sticky=tk.W, pady=4)
        self.passphrase_confirm = ttk.Entry(pass_lf, width=40, show="•")
        self.passphrase_confirm.grid(row=1, column=1, sticky=tk.W, padx=5, pady=4)

        self.show_pass = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            pass_lf,
            text="Show passphrase",
            variable=self.show_pass,
            command=self._toggle_pass_visibility,
        ).grid(row=2, column=1, sticky=tk.W, padx=5, pady=4)

        self.encrypt_keys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            pass_lf,
            text="Encrypt keys file at rest (.lf256.keys.enc)",
            variable=self.encrypt_keys_var,
        ).grid(row=3, column=1, sticky=tk.W, padx=5, pady=4)

        # --- 4. Actions ---
        act_lf = ttk.LabelFrame(main, text=" 4. Seal / Unseal ", padding="10")
        act_lf.pack(fill=tk.X, pady=(0, 8))

        btn_row = ttk.Frame(act_lf)
        btn_row.pack(fill=tk.X, pady=6)
        ttk.Button(
            btn_row,
            text="Seal Payload (encrypt)",
            style="Accent.TButton",
            command=lambda: self._run_thread(self._seal_payload),
        ).pack(side=tk.LEFT, padx=8, expand=True, fill=tk.X)
        ttk.Button(
            btn_row,
            text="Unseal Payload (decrypt)",
            style="Accent.TButton",
            command=lambda: self._run_thread(self._unseal_payload),
        ).pack(side=tk.RIGHT, padx=8, expand=True, fill=tk.X)

        self.progress = ttk.Progressbar(main, mode="indeterminate")
        self.progress.pack(fill=tk.X, pady=6)

        self.status = ttk.Label(main, text="State: IDLE", style="Status.TLabel")
        self.status.pack(anchor=tk.W)

        hint = (
            "Decrypt needs: map + keys + .enc + correct passphrase.\n"
            "Distribute map to peers for network chat; keep keys restricted."
        )
        ttk.Label(main, text=hint, foreground="#555", wraplength=680).pack(anchor=tk.W, pady=(8, 0))

    def _toggle_pass_visibility(self) -> None:
        show = "" if self.show_pass.get() else "•"
        self.passphrase_entry.config(show=show)
        self.passphrase_confirm.config(show=show)

    def _browse_map(self) -> None:
        path = filedialog.askopenfilename(
            title="Import key map",
            filetypes=[("LF-256 map", "*.lf256.map.json"), ("JSON", "*.json"), ("All", "*.*")],
        )
        if path:
            self.map_path.set(path)

    def _browse_keys(self) -> None:
        path = filedialog.askopenfilename(
            title="Import keys",
            filetypes=[("LF-256 keys", "*.lf256.keys.json"), ("JSON", "*.json"), ("All", "*.*")],
        )
        if path:
            self.keys_path.set(path)

    def _browse_enc(self) -> None:
        path = filedialog.askopenfilename(
            title="Import ciphertext",
            filetypes=[("LF-256 ciphertext", "*.lf256.enc"), ("All", "*.*")],
        )
        if path:
            self.enc_path.set(path)

    def _browse_plain(self) -> None:
        path = filedialog.askopenfilename(title="Select plaintext to seal")
        if path:
            self.plain_path.set(path)

    def _set_status(self, text: str, busy: bool = False) -> None:
        self.status.config(text=f"State: {text}")
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()

    def _run_thread(self, target) -> None:
        threading.Thread(target=target, daemon=True).start()

    def _get_passphrase(self, *, confirm: bool) -> str | None:
        p1 = self.passphrase_entry.get()
        if confirm:
            p2 = self.passphrase_confirm.get()
            if p1 != p2:
                messagebox.showerror("Passphrase", "Passphrase and confirmation do not match.")
                return None
        if not p1:
            messagebox.showerror("Passphrase", "Enter a passphrase (not stored in map/keys files).")
            return None
        return p1

    def _generate_map_thread(self) -> None:
        self._run_thread(self._generate_map)

    def _generate_map(self) -> None:
        out = filedialog.asksaveasfilename(
            title="Save new key map",
            defaultextension=".lf256.map.json",
            filetypes=[("LF-256 map", "*.lf256.map.json")],
        )
        if not out:
            return

        self._set_status("Generating network key map…", busy=True)
        try:
            doc = LF256KeyMap.create_network_map()
            LF256KeyMap.save_map(out, doc)
            self.map_path.set(out)
            self._set_status("IDLE")
            messagebox.showinfo(
                "Key map created",
                f"Map saved:\n{out}\n\nPassphrase was NOT included. "
                "Enter it manually when sealing or unsealing.",
            )
        except Exception as exc:
            self._set_status(f"ERROR: {exc}")
            messagebox.showerror("Generate map failed", str(exc))

    def _seal_payload(self) -> None:
        plain = self.plain_path.get().strip()
        if not plain or not Path(plain).is_file():
            messagebox.showerror("Input", "Select a valid plaintext file to seal.")
            return

        passphrase = self._get_passphrase(confirm=True)
        if passphrase is None:
            return

        map_out = filedialog.asksaveasfilename(
            title="Save map file",
            defaultextension=".lf256.map.json",
            initialfile="payload.lf256.map.json",
            filetypes=[("LF-256 map", "*.lf256.map.json")],
        )
        if not map_out:
            return
        if self.encrypt_keys_var.get():
            keys_out = filedialog.asksaveasfilename(
                title="Save encrypted keys file",
                defaultextension=LF256KeyMap.KEYS_ENC_SUFFIX,
                initialfile=f"payload{LF256KeyMap.KEYS_ENC_SUFFIX}",
                filetypes=[("LF-256 encrypted keys", f"*{LF256KeyMap.KEYS_ENC_SUFFIX}")],
            )
        else:
            keys_out = filedialog.asksaveasfilename(
                title="Save keys file",
                defaultextension=LF256KeyMap.KEYS_SUFFIX,
                initialfile=f"payload{LF256KeyMap.KEYS_SUFFIX}",
                filetypes=[("LF-256 keys", f"*{LF256KeyMap.KEYS_SUFFIX}")],
            )
        if not keys_out:
            return
        enc_out = filedialog.asksaveasfilename(
            title="Save ciphertext",
            defaultextension=".lf256.enc",
            initialfile="payload.lf256.enc",
            filetypes=[("LF-256 ciphertext", "*.lf256.enc")],
        )
        if not enc_out:
            return

        self._set_status("Sealing payload (lattice + passphrase)…", busy=True)
        try:
            plaintext = Path(plain).read_bytes()
            map_doc, keys_doc, ciphertext = LF256KeyMap.seal_payload(plaintext, passphrase)

            LF256KeyMap.save_map(map_out, map_doc)
            sk = keys_doc["keys"]["private_key_s"]
            if self.encrypt_keys_var.get():
                LF256KeyMap.save_keys_encrypted(keys_out, sk, passphrase)
            else:
                LF256KeyMap.save_keys(keys_out, sk)
            Path(enc_out).write_bytes(ciphertext)

            self.map_path.set(map_out)
            self.keys_path.set(keys_out)
            self.enc_path.set(enc_out)

            self._set_status("IDLE")
            messagebox.showinfo(
                "Sealed",
                f"Map:  {map_out}\nKeys: {keys_out}\nEnc:  {enc_out}\n\n"
                "Passphrase was not written to disk.",
            )
        except Exception as exc:
            self._set_status(f"ERROR: {exc}")
            messagebox.showerror("Seal failed", str(exc))

    def _unseal_payload(self) -> None:
        map_p = self.map_path.get().strip()
        keys_p = self.keys_path.get().strip()
        enc_p = self.enc_path.get().strip()

        if not map_p or not Path(map_p).is_file():
            messagebox.showerror("Import", "Import a valid .lf256.map.json file.")
            return
        if not keys_p or not Path(keys_p).is_file():
            messagebox.showerror("Import", "Import a valid keys file (.json or .keys.enc).")
            return
        if not enc_p or not Path(enc_p).is_file():
            messagebox.showerror("Import", "Import a valid .lf256.enc ciphertext file.")
            return

        passphrase = self._get_passphrase(confirm=False)
        if passphrase is None:
            return

        out = filedialog.asksaveasfilename(title="Save restored plaintext")
        if not out:
            return

        self._set_status("Unsealing payload…", busy=True)
        try:
            map_doc = LF256KeyMap.load_map(map_p)
            sk = LF256KeyMap.load_keys_auto(keys_p, passphrase)
            keys_doc = {
                "lf256_version": LF256KeyMap.VERSION,
                "keys": {"private_key_s": sk},
            }
            ciphertext = Path(enc_p).read_bytes()
            plaintext = LF256KeyMap.unseal_payload(map_doc, keys_doc, ciphertext, passphrase)
            Path(out).write_bytes(plaintext)

            self._set_status("IDLE")
            messagebox.showinfo("Unsealed", f"Restored plaintext:\n{out}")
        except (AeadDecryptError, KEMDecapsulationError) as exc:
            self._set_status(f"ERROR: {exc}")
            messagebox.showerror(
                "Unseal failed",
                f"{exc}\n\nWrong passphrase or mismatched map/keys/enc files.",
            )
        except UnicodeDecodeError:
            self._set_status("ERROR: invalid keys file format")
            messagebox.showerror(
                "Unseal failed",
                "Keys file looks encrypted but was opened as text.\n\n"
                "Use the same passphrase and the .lf256.keys.enc file from sealing, "
                "or re-seal with encrypted keys checked.",
            )
        except Exception as exc:
            self._set_status(f"ERROR: {exc}")
            messagebox.showerror(
                "Unseal failed",
                f"{exc}\n\nCheck map, keys, enc paths and passphrase match the seal step.",
            )


def main() -> None:
    root = tk.Tk()
    LF256StorageVaultGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
