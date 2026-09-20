"""
David Secure - Antivirus Engine
================================
Desktop application (Tkinter) that simulates an antivirus engine with
real hash-based scanning, quarantine, and process monitoring features.

This file is an expanded version of the original project with improvements in
robustness, persistence, usability, and performance. It is an educational /
portfolio project: it does not replace a commercial antivirus solution.

GUI mode:   python david_secure.py
CLI mode:   python david_secure.py --scan quick
            python david_secure.py --scan full --path "/path/to/scan"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import uuid
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

try:
    import psutil
except ImportError:  # Improvement: app doesn't crash if the optional dependency is missing
    psutil = None


# --------------------------------------------------------------------------- #
# Application constants and paths
# --------------------------------------------------------------------------- #
APP_NAME = "David Secure"
APP_VERSION = "4.0.0"

APP_DIR = Path.home() / ".david_secure"
CONFIG_PATH = APP_DIR / "config.json"
QUARANTINE_META_PATH = APP_DIR / "quarantine_meta.json"
SIGNATURES_PATH = APP_DIR / "signatures.json"
LOG_DIR = APP_DIR / "logs"
QUARANTINE_DIR = Path.home() / "DavidSecure_Quarantine"

DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv",
    "$RECYCLE.BIN", "System Volume Information", ".Trash",
}
SUSPICIOUS_DOUBLE_EXTENSIONS = (
    ".pdf.exe", ".docx.exe", ".jpg.exe", ".txt.exe", ".png.exe",
    ".xlsx.exe", ".zip.exe", ".mp3.exe", ".pptx.exe",
)
DEFAULT_SUSPICIOUS_PROCESSES = ["mimikatz.exe", "nc.exe", "netcat.exe", "keylogger.exe"]

HASH_BUFFER_SIZE = 65536


# Static XOR key to "obfuscate" quarantined files and make them non-executable
QUARANTINE_XOR_KEY = 0x5A
# Common suspicious parameters found in exploitation tools
SUSPICIOUS_ARGUMENTS = {"sekurlsa::", "lsadump::", "-lvp", "-le", "exec cmd.exe"}
# ----------------------
# Color palette: light theme (original) and dark theme (new)
THEMES = {
    "light": {
        "bg_main": "#0099E6", "bg_nav": "#3131A1", "bg_card": "#0077B3",
        "fg_text": "white", "fg_title": "black",
        "accent_ok": "#66FF33", "accent_warn": "#FF4D4D",
        "accent_info": "#80D4FF", "accent_seg": "#FF7F00",
        "log_bg": "white", "log_fg": "black",
    },
    "dark": {
        "bg_main": "#101820", "bg_nav": "#1B2430", "bg_card": "#1E2A38",
        "fg_text": "#E8F1F5", "fg_title": "#E8F1F5",
        "accent_ok": "#4CD964", "accent_warn": "#FF6B6B",
        "accent_info": "#4FC3F7", "accent_seg": "#FFB74D",
        "log_bg": "#0B0F14", "log_fg": "#B8F397",
    },
}


# --------------------------------------------------------------------------- #
# Pure utilities (no GUI) — reusable in CLI mode as well
# --------------------------------------------------------------------------- #
def ensure_app_dirs() -> None:
    """Creates the config, logs, and quarantine directories if they don't exist."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def setup_logger() -> logging.Logger:
    """Logger with file rotation (2 MB x 3 backups) instead of console-only."""
    logger = logging.getLogger("david_secure")
    if logger.handlers:  # avoids duplicate handlers if called more than once
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "david_secure.log", maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


def human_readable_size(num_bytes: float) -> str:
    """Converts bytes into a readable unit (KB, MB, GB...)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def load_json(path: Path, default):
    """Loads JSON resiliently: if the file doesn't exist or is corrupted,
    returns the default value instead of crashing the application."""
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return default


def save_json(path: Path, data) -> bool:
    """Atomic save: writes to a temporary file and then replaces it,
    preventing leaving a half-written JSON if the process is interrupted."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, path)
        return True
    except OSError:
        return False


def default_config() -> dict:
    return {
        "theme": "light",
        "autoprotection": False,
        "exclusions": [],
        "max_hash_size_mb": 200,
        "monitor_interval_seconds": 5,
        "process_whitelist": [],
        "last_scan": None,        # dict: {type, date, scanned, threats, duration_sec}
        "scan_history": [],       # list of the last scans
        "window_geometry": "1100x650",
    }


def load_config() -> dict:
    cfg = default_config()
    cfg.update(load_json(CONFIG_PATH, {}))
    return cfg


def save_config(config: dict) -> None:
    save_json(CONFIG_PATH, config)


def default_signatures() -> list:
    """Test signatures. IMPORTANT (bug fix): the original file calculated
    SHA-256 but compared against MD5 hashes, so detection NEVER matched.
    Now each signature declares its algorithm and the scanner calculates
    both hashes in a single pass per file."""
    return [
        {"hash": "44d88612fea8a8f36de82e1278abb02f", "algo": "md5",
         "name": "EICAR Test File (standard test file, not a real virus)"},
        {"hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0", "algo": "sha256",
         "name": "EICAR Test File (standard test file, not a real virus)"},
        {"hash": "5d41402abc4b2a76b9719d911017c592", "algo": "md5",
         "name": "Malware.Simulated.1"},
        {"hash": "7d793037a0760186574b0282f2f435e7", "algo": "md5",
         "name": "Trojan.Generic.Test"},
    ]


def load_signatures() -> list:
    sigs = load_json(SIGNATURES_PATH, None)
    if not sigs:
        sigs = default_signatures()
        save_json(SIGNATURES_PATH, sigs)
    return sigs


def merge_signatures_from_file(path: str) -> tuple[list, int]:
    """Merges external signatures (JSON) with the already loaded signatures,
    without duplicating. Expected format:
    [{"hash": "...", "algo": "md5"|"sha256", "name": "..."}]"""
    current = load_signatures()
    existing_hashes = {(s["hash"].lower(), s["algo"]) for s in current}
    with open(path, "r", encoding="utf-8") as f:
        new_sigs = json.load(f)
    added = 0
    for sig in new_sigs:
        key = (sig.get("hash", "").lower(), sig.get("algo", "sha256"))
        if key[0] and key not in existing_hashes:
            current.append({"hash": key[0], "algo": key[1], "name": sig.get("name", "Unnamed signature")})
            existing_hashes.add(key)
            added += 1
    save_json(SIGNATURES_PATH, current)
    return current, added


def load_quarantine_records() -> list:
    return load_json(QUARANTINE_META_PATH, [])


def save_quarantine_records(records: list) -> None:
    save_json(QUARANTINE_META_PATH, records)


def compute_hashes(filepath: str, max_size_bytes: Optional[int] = None) -> Optional[dict]:
    """Calculates MD5 and SHA-256 in a single read pass (previously the file
    would have had to be read twice to compare against both types of
    signatures). Returns None if the file can't be read or exceeds the
    configured maximum size (to avoid hanging the scan with huge files)."""
    try:
        if max_size_bytes is not None and os.path.getsize(filepath) > max_size_bytes:
            return None
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            buf = f.read(HASH_BUFFER_SIZE)
            while buf:
                md5.update(buf)
                sha256.update(buf)
                buf = f.read(HASH_BUFFER_SIZE)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
    except (PermissionError, FileNotFoundError, OSError):
        return None


def match_signature(hashes: dict, signatures: list) -> Optional[str]:
    """Compares the calculated hashes against the signature database and
    returns the threat name if there's a match."""
    for sig in signatures:
        value = hashes.get(sig["algo"])
        if value and value.lower() == sig["hash"].lower():
            return sig["name"]
    return None


def is_excluded(dirpath: str, exclusions: list) -> bool:
    """Determines whether a folder should be skipped (user exclusions plus
    well-known system folders that cause noise/permission errors)."""
    base = os.path.basename(dirpath)
    if base in DEFAULT_EXCLUDED_DIRS:
        return True
    normalized = os.path.normcase(os.path.abspath(dirpath))
    for excl in exclusions:
        if normalized.startswith(os.path.normcase(os.path.abspath(excl))):
            return True
    return False


def quarantine_move(filepath: str, quarantine_dir: Path) -> Optional[str]:
    """Moves a file to quarantine, encrypts its contents to deactivate it,
    and removes all OS execution permissions."""
    try:
        filename = os.path.basename(filepath)
        dest = quarantine_dir / f"{filename}.locked"

        if dest.exists():
            stem, _ = os.path.splitext(filename)
            dest = quarantine_dir / f"{stem}_{uuid.uuid4().hex[:8]}.locked"

        with open(filepath, "rb") as f_in:
            data = f_in.read()

        encrypted_data = bytearray(b ^ QUARANTINE_XOR_KEY for b in data)

        with open(dest, "wb") as f_out:
            f_out.write(encrypted_data)

        os.remove(filepath)
        os.chmod(str(dest), 0o000)

        return str(dest)
    except OSError:
        return None



def open_folder_in_explorer(path: str) -> None:
    """Opens a folder in the operating system's file explorer."""
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Reusable Tooltip
# --------------------------------------------------------------------------- #
class ToolTip:
    """Small help bubble that appears when hovering over a widget."""

    def __init__(self, widget: tk.Widget, text: str):
        self.widget = widget
        self.text = text
        self.tip_window: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self.text, bg="#FFFFE0", fg="black", relief="solid",
                 borderwidth=1, font=("Arial", 9), padx=6, pady=3).pack()

    def _hide(self, _event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


# --------------------------------------------------------------------------- #
# Main application
# --------------------------------------------------------------------------- #
class DavidSecureApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        ensure_app_dirs()
        self.logger = setup_logger()

        self.config = load_config()
        self.signatures = load_signatures()
        self.quarantine_dir = QUARANTINE_DIR

        self.autoprotection_active = tk.BooleanVar(value=self.config.get("autoprotection", False))
        self.blocked_threats = load_quarantine_records()
        self.log_buffer: list[str] = []   # log is no longer lost when switching tabs
        self.filter_var = tk.StringVar(value="")

        self.state_lock = threading.Lock()
        self.monitoring = self.autoprotection_active.get()
        self.monitor_stop_event = threading.Event()   # allows cleanly stopping the thread
        self.scan_cancel_event = threading.Event()
        self.scan_running = False

        self.root.title(f"{APP_NAME} - Antivirus Engine  v{APP_VERSION}")
        self.root.geometry(self.config.get("window_geometry", "1100x650"))
        self.root.minsize(900, 550)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Keyboard shortcuts
        self.root.bind("<F5>", lambda e: self.start_scan("Quick"))
        self.root.bind("<Control-q>", lambda e: self.on_close())

        self.build_ui()

        if psutil is None:
            self.log("[Warning] The 'psutil' module is not installed: real-time "
                      "protection is disabled. Install it with: pip install psutil")
        else:
            threading.Thread(target=self.background_monitor, daemon=True).start()

    # ------------------------------------------------------------------- #
    # UI construction / rebuild (light/dark theme)
    # ------------------------------------------------------------------- #
    def build_ui(self):
        self.colors = THEMES[self.config.get("theme", "light")]
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.configure(bg=self.colors["bg_main"])

        # --- LEFT PANEL (Navigation) ---
        self.left_frame = tk.Frame(self.root, bg=self.colors["bg_nav"], width=300)
        self.left_frame.pack(side="left", fill="y")
        self.left_frame.pack_propagate(False)

        self.logo_canvas = tk.Canvas(self.left_frame, width=280, height=100,
                                      bg=self.colors["bg_nav"], highlightthickness=0)
        self.logo_canvas.pack(pady=(20, 0))
        self._draw_logo(self.logo_canvas, canvas_width=280, canvas_height=100)

        # Protection status indicator (green/red dot)
        status_frame = tk.Frame(self.left_frame, bg=self.colors["bg_nav"])
        status_frame.pack(pady=(0, 10))
        self.status_canvas = tk.Canvas(status_frame, width=16, height=16,
                                        bg=self.colors["bg_nav"], highlightthickness=0)
        self.status_canvas.pack(side="left", padx=(0, 6))
        self.status_dot = self.status_canvas.create_oval(2, 2, 14, 14, fill="#FF4D4D", outline="")
        self.status_label = tk.Label(status_frame, text="Unprotected", bg=self.colors["bg_nav"],
                                      fg=self.colors["fg_text"], font=("Arial", 10))
        self.status_label.pack(side="left")
        self._refresh_status_indicator()

        btn_style = {"bg": self.colors["bg_nav"], "fg": "white", "font": ("Arial", 16),
                     "bd": 0, "anchor": "w", "padx": 20, "cursor": "hand2"}

        nav_items = [
            ("Info  ⓘ", "info", self.colors["accent_info"]),
            ("Security  🛡️", "security", self.colors["accent_seg"]),
            ("Accounts  👤", "accounts", self.colors["accent_ok"]),
            ("Device  🖥️", "device", "#B3B3B3"),
            ("ISSUES  ❗", "issues", self.colors["accent_warn"]),
            ("Settings  ⚙️", "settings", "#CCCCCC"),
        ]
        for text, frame_name, color in nav_items:
            b = tk.Button(self.left_frame, text=text, command=lambda f=frame_name: self.show_frame(f), **btn_style)
            b.configure(fg=color)
            b.pack(fill="x", pady=10)

        version_lbl = tk.Label(self.left_frame, text=f"v{APP_VERSION}", bg=self.colors["bg_nav"],
                                fg="#8888AA", font=("Arial", 9))
        version_lbl.pack(side="bottom", pady=10)

        # --- RIGHT PANEL (Content) ---
        self.right_frame = tk.Frame(self.root, bg=self.colors["bg_main"])
        self.right_frame.pack(side="right", fill="both", expand=True)

        self.content_frame = tk.Frame(self.right_frame, bg=self.colors["bg_main"])
        self.content_frame.pack(fill="both", expand=True, padx=30, pady=20)

        self.show_frame("security")

    def _draw_logo(self, canvas: tk.Canvas, canvas_width: int, canvas_height: int):
        """Draws the icon + 'David' + 'Secure' centered and without overlap.

        Improvement: the original used fixed text coordinates (x=80 and x=160)
        that assumed a specific character width. With the 28pt Arial Bold font,
        'David' actually measures ~107px and ends at x=187, meaning it overlaps
        27px of the start of 'Secure' at x=160 (they overlap, especially noticeable
        on Linux/Mac where the system's 'Arial' can render even wider). Here the
        actual text is measured with tkinter.font, the font size is reduced if
        needed to fit the available width, and the entire block (icon + text) is
        centered on the canvas.
        """
        import tkinter.font as tkfont

        icon_w, icon_h = 40, 60          # same icon size as the original
        gap_icon_text = 14               # space between icon and "David"
        gap_words = 7                    # space between "David" and "Secure"
        padding = 8
        available_width = canvas_width - 2 * padding

        font_size = 28
        min_font_size = 15
        while font_size >= min_font_size:
            f = tkfont.Font(family="Arial", size=font_size, weight="bold")
            w_david = f.measure("David")
            w_secure = f.measure("Secure")
            total_width = icon_w + gap_icon_text + w_david + gap_words + w_secure
            if total_width <= available_width:
                break
            font_size -= 1
        else:
            f = tkfont.Font(family="Arial", size=min_font_size, weight="bold")
            w_david = f.measure("David")
            w_secure = f.measure("Secure")
            total_width = icon_w + gap_icon_text + w_david + gap_words + w_secure

        start_x = max(padding, (canvas_width - total_width) / 2)
        ix, iy = start_x, (canvas_height - icon_h) / 2  # icon vertically centered
        text_y = canvas_height / 2

        # Icon (same proportions as the original, now repositionable)
        def m(x, y):
            """Translates the original coordinates (based at x=30,y=20) to the
            new origin (ix, iy), preserving the exact shape of the icon."""
            return (ix + (x - 30), iy + (y - 20))

        canvas.create_polygon(*m(30, 20), *m(50, 20), *m(50, 80), *m(30, 60), fill="#FF0000", outline="")
        canvas.create_polygon(*m(50, 20), *m(70, 20), *m(70, 60), *m(50, 80), fill="#FFFF00", outline="")
        canvas.create_polygon(*m(58, 35), *m(68, 35), *m(55, 70), *m(45, 35), *m(52, 35), *m(55, 55),
                               fill="#FF7F00", outline="")

        x_david = ix + icon_w + gap_icon_text
        canvas.create_text(x_david, text_y, text="David", fill=self.colors["fg_text"],
                            font=("Arial", font_size, "bold"), anchor="w")
        x_secure = x_david + w_david + gap_words
        canvas.create_text(x_secure, text_y, text="Secure", fill="#FF7F00",
                            font=("Arial", font_size, "bold"), anchor="w")

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_frame(self, frame_name):
        self.clear_content()
        builders: dict[str, Callable[[], None]] = {
            "info": self.build_info,
            "security": self.build_security,
            "accounts": self.build_accounts,
            "device": self.build_device,
            "issues": self.build_issues,
            "settings": self.build_settings,
        }
        builders.get(frame_name, self.build_security)()

    # ------------------------------------------------------------------- #
    # Tab: Info
    # ------------------------------------------------------------------- #
    def build_info(self):
        c = self.colors
        tk.Label(self.content_frame, text="Information", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w")
        data = [
            f"Antivirus Name: {APP_NAME} Engine",
            f"Version: {APP_VERSION} (Open Source)",
            "Platform: Windows, macOS, Linux",
            f"Loaded signatures: {len(self.signatures)}",
            f"psutil available: {'Yes' if psutil else 'No (real-time protection disabled)'}",
        ]
        for d in data:
            tk.Label(self.content_frame, text=d, bg=c["bg_main"], fg=c["fg_text"],
                      font=("Arial", 18)).pack(anchor="w", pady=8)
        tk.Label(self.content_frame, text="Architecture: Hash-based scanning (MD5 + SHA-256) and "
                  "double-extension heuristics", bg=c["bg_main"], fg="#CCFFFF",
                  font=("Arial", 14, "italic")).pack(anchor="w", pady=30)

        tk.Button(self.content_frame, text="About / Legal notice", command=self.show_about,
                  bg=c["bg_card"], fg="white", font=("Arial", 12), bd=0, padx=10, pady=6,
                  cursor="hand2").pack(anchor="w")

    def show_about(self):
        top = tk.Toplevel(self.root)
        top.title(f"About {APP_NAME}")
        top.geometry("480x260")
        top.configure(bg=self.colors["bg_main"])
        text = (
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "Educational / portfolio project that simulates an antivirus engine:\n"
            "hash-based scanning, simple heuristics, and file quarantine.\n\n"
            "This software does NOT replace a commercial antivirus solution nor "
            "does it offer any detection guarantees. Use at your own risk and always "
            "keep your real antivirus up to date."
        )
        tk.Label(top, text=text, bg=self.colors["bg_main"], fg=self.colors["fg_text"],
                  font=("Arial", 11), justify="left", wraplength=440).pack(padx=15, pady=15)
        tk.Button(top, text="Close", command=top.destroy).pack(pady=10)

    # ------------------------------------------------------------------- #
    # Tab: Security (scanning)
    # ------------------------------------------------------------------- #
    def build_security(self):
        c = self.colors
        title_frame = tk.Frame(self.content_frame, bg=c["bg_main"])
        title_frame.pack(fill="x", pady=(0, 15))
        tk.Label(title_frame, text="| Scan", bg=c["bg_main"], fg=c["fg_title"], font=("Arial", 36)).pack(side="left")
        tk.Label(title_frame, text="🔍", bg=c["bg_main"], fg=c["fg_title"], font=("Arial", 30)).pack(side="left", padx=10)

        btn_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        btn_row.pack(pady=5)

        self.btn_quick = tk.Button(btn_row, text="Quick", bg="#5CB85C", fg="white", font=("Arial", 18),
                                     bd=0, width=13, height=2, cursor="hand2",
                                     command=lambda: self.start_scan("Quick"))
        self.btn_quick.grid(row=0, column=0, padx=5)
        ToolTip(self.btn_quick, "Scans Downloads, Desktop, and Temporary folders (F5)")

        self.btn_full = tk.Button(btn_row, text="Full", bg="black", fg="white", font=("Arial", 18),
                                       bd=0, width=13, height=2, cursor="hand2",
                                       command=lambda: self.start_scan("Full"))
        self.btn_full.grid(row=0, column=1, padx=5)
        ToolTip(self.btn_full, "Scans your entire user folder (slower)")

        self.btn_custom = tk.Button(btn_row, text="Custom", bg="#337AB7", fg="white",
                                            font=("Arial", 18), bd=0, width=13, height=2, cursor="hand2",
                                            command=self.start_custom_scan)
        self.btn_custom.grid(row=0, column=2, padx=5)
        ToolTip(self.btn_custom, "Choose which folder to scan yourself")

        self.btn_stop = tk.Button(self.content_frame, text="⏹ Stop scan", bg=c["accent_warn"],
                                   fg="white", font=("Arial", 12), bd=0, padx=10, pady=4,
                                   cursor="hand2", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(pady=8)

        chk_auto = tk.Checkbutton(self.content_frame, text="Let David Secure protect you automatically",
                                   variable=self.autoprotection_active, bg=c["bg_main"], fg=c["fg_text"],
                                   font=("Arial", 14), activebackground=c["bg_main"], selectcolor="black",
                                   command=self.toggle_autoprotection,
                                   state="normal" if psutil else "disabled")
        chk_auto.pack(pady=15, anchor="w")

        info_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        info_row.pack(fill="x", anchor="w")
        tk.Label(info_row, text=f"Loaded signatures: {len(self.signatures)}", bg=c["bg_main"],
                  fg="#CCFFFF", font=("Arial", 11)).pack(side="left", padx=(0, 20))
        last = self.config.get("last_scan")
        last_txt = "Last scan: never" if not last else (
            f"Last scan: {last['type']} on {last['date']} "
            f"({last['threats']} threat(s), {last['scanned']} files)")
        self.lbl_last_scan = tk.Label(info_row, text=last_txt, bg=c["bg_main"], fg="#CCFFFF", font=("Arial", 11))
        self.lbl_last_scan.pack(side="left")

        self.progress = ttk.Progressbar(self.content_frame, mode="indeterminate", length=400)
        self.progress.pack(pady=(10, 0), fill="x")
        self.progress_label = tk.Label(self.content_frame, text="", bg=c["bg_main"], fg=c["fg_text"],
                                        font=("Arial", 10))
        self.progress_label.pack(anchor="w")

        self.log_text = tk.Text(self.content_frame, height=8, width=60, bg=c["log_bg"], fg=c["log_fg"],
                                 font=("Consolas", 11), bd=3, relief="solid")
        self.log_text.pack(pady=10, fill="both", expand=True)
        if self.log_buffer:
            self.log_text.insert("end", "\n".join(self.log_buffer) + "\n")
        else:
            self.log_text.insert("end", "David Secure ready. Awaiting instructions...\n")
        self.log_text.config(state="disabled")

        log_btns = tk.Frame(self.content_frame, bg=c["bg_main"])
        log_btns.pack(anchor="e", pady=(0, 5))
        tk.Button(log_btns, text="Copy log", command=self.copy_log_to_clipboard, bg=c["bg_card"],
                  fg="white", bd=0, padx=8, pady=3, cursor="hand2").pack(side="left", padx=4)
        tk.Button(log_btns, text="Export report", command=self.export_report, bg=c["bg_card"],
                  fg="white", bd=0, padx=8, pady=3, cursor="hand2").pack(side="left", padx=4)

        if self.scan_running:
            self._set_scan_buttons_state("disabled")
            self.progress.start(15)

    def start_custom_scan(self):
        folder = filedialog.askdirectory(title="Select the folder to scan")
        if folder:
            self.start_scan("Custom", custom_path=folder)

    def copy_log_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.log_buffer))
        messagebox.showinfo(APP_NAME, "Log copied to clipboard.")

    def export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text file", "*.txt")],
                                             initialfile="david_secure_report.txt")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"{APP_NAME} Report v{APP_VERSION} - {datetime.now().isoformat(timespec='seconds')}\n")
                f.write("=" * 60 + "\n\n")
                f.write("\n".join(self.log_buffer))
                f.write("\n\nThreats in quarantine:\n")
                for r in self.blocked_threats:
                    f.write(f" - {r.get('filename')} | {r.get('threat_name')} | {r.get('date')}\n")
            messagebox.showinfo(APP_NAME, f"Report saved to:\n{path}")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Could not save the report: {e}")

    # ------------------------------------------------------------------- #
    # Tab: Accounts
    # ------------------------------------------------------------------- #
    def build_accounts(self):
        c = self.colors
        tk.Label(self.content_frame, text="Account Security", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 10))
        tk.Label(self.content_frame, text="(Demo data — does not connect to any real service)",
                  bg=c["bg_main"], fg="#CCFFFF", font=("Arial", 11, "italic")).pack(anchor="w", pady=(0, 15))
        accounts = [("Email", "Secure", c["accent_ok"]),
                    ("Social Media", "Leaked Password", c["accent_warn"]),
                    ("Online Banking", "Secure (2FA)", c["accent_ok"])]
        for account, status, color in accounts:
            frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
            frame.pack(fill="x", pady=5)
            tk.Label(frame, text=account, bg=c["bg_card"], fg=c["fg_text"], font=("Arial", 16)).pack(side="left")
            tk.Label(frame, text=status, bg=c["bg_card"], fg=color, font=("Arial", 16, "bold")).pack(side="right")

    # ------------------------------------------------------------------- #
    # Tab: Device
    # ------------------------------------------------------------------- #
    def build_device(self):
        c = self.colors
        tk.Label(self.content_frame, text="Device Security", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 20))

        info = [("Operating System", platform.system()), ("Kernel", platform.release()),
                ("Architecture", platform.machine()), ("Quarantine Folder", str(self.quarantine_dir))]
        if psutil:
            info.append(("CPU Usage", f"{psutil.cpu_percent(interval=0.2)} %"))
            info.append(("RAM Usage", f"{psutil.virtual_memory().percent} %"))
        quarantine_size = sum(f.stat().st_size for f in self.quarantine_dir.glob("*") if f.is_file())
        info.append(("Quarantine Size", human_readable_size(quarantine_size)))
        info.append(("Files in quarantine", str(len(self.blocked_threats))))

        for item, value in info:
            frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
            frame.pack(fill="x", pady=5)
            tk.Label(frame, text=item, bg=c["bg_card"], fg=c["fg_text"], font=("Arial", 16)).pack(side="left")
            tk.Label(frame, text=value, bg=c["bg_card"], fg=c["accent_ok"], font=("Arial", 14, "bold")).pack(side="right")

        tk.Button(self.content_frame, text="Open quarantine folder",
                  command=lambda: open_folder_in_explorer(str(self.quarantine_dir)),
                  bg=c["bg_card"], fg="white", bd=0, padx=10, pady=6, cursor="hand2").pack(anchor="w", pady=15)

    # ------------------------------------------------------------------- #
    # Tab: Issues / Quarantine
    # ------------------------------------------------------------------- #
    def build_issues(self):
        c = self.colors
        tk.Label(self.content_frame, text="Blocked Threats / Quarantine", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 15))

        top_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        top_row.pack(fill="x", pady=(0, 10))
        tk.Label(top_row, text="Search:", bg=c["bg_main"], fg=c["fg_text"], font=("Arial", 12)).pack(side="left")
        entry = tk.Entry(top_row, textvariable=self.filter_var, font=("Arial", 12), width=30)
        entry.pack(side="left", padx=8)
        entry.bind("<KeyRelease>", lambda e: self.show_frame("issues"))
        tk.Button(top_row, text="Empty quarantine", command=self.empty_quarantine, bg=c["accent_warn"],
                  fg="white", bd=0, padx=10, pady=4, cursor="hand2").pack(side="right")

        filter_text = self.filter_var.get().lower().strip()
        records = [r for r in self.blocked_threats if filter_text in r.get("filename", "").lower()] \
            if filter_text else self.blocked_threats

        if not records:
            tk.Label(self.content_frame, text="No threats detected.", bg=c["bg_main"], fg=c["fg_text"],
                      font=("Arial", 16)).pack(anchor="w")
            return

        canvas_container = tk.Frame(self.content_frame, bg=c["bg_main"])
        canvas_container.pack(fill="both", expand=True)
        canvas = tk.Canvas(canvas_container, bg=c["bg_main"], highlightthickness=0)
        scrollbar = tk.Scrollbar(canvas_container, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=c["bg_main"])
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for record in records:
            frame = tk.Frame(scroll_frame, bg=c["accent_warn"], pady=8, padx=10)
            frame.pack(fill="x", pady=4)
            text = f"⚠️  {record.get('filename')} — {record.get('threat_name')} ({record.get('date', '')})"
            tk.Label(frame, text=text, bg=c["accent_warn"], fg="white", font=("Arial", 12),
                      anchor="w").pack(side="left", fill="x", expand=True)
            tk.Button(frame, text="Restore", command=lambda r=record: self.restore_from_quarantine(r),
                      bg="white", fg="black", bd=0, padx=6, cursor="hand2").pack(side="right", padx=4)
            tk.Button(frame, text="Delete", command=lambda r=record: self.delete_permanently(r),
                      bg="black", fg="white", bd=0, padx=6, cursor="hand2").pack(side="right", padx=4)

    def restore_from_quarantine(self, record: dict):
        source = record.get("quarantine_path")
        destination = record.get("original_path")
        if not source or not os.path.exists(source):
            messagebox.showerror(APP_NAME, "The file in quarantine no longer exists.")
            return
        if not messagebox.askyesno(APP_NAME, f"Restore '{record.get('filename')}' to its original location?\n"
                                              "This may be risky if the file was a real threat."):
            return
        try:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.move(source, destination)
            self.blocked_threats = [r for r in self.blocked_threats if r is not record]
            save_quarantine_records(self.blocked_threats)
            self.log(f"File restored: {record.get('filename')}")
            self.show_frame("issues")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Could not restore: {e}")

    def delete_permanently(self, record: dict):
        if not messagebox.askyesno(APP_NAME, f"Permanently delete '{record.get('filename')}'?"):
            return
        source = record.get("quarantine_path")
        try:
            if source and os.path.exists(source):
                os.remove(source)
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Could not delete: {e}")
            return
        self.blocked_threats = [r for r in self.blocked_threats if r is not record]
        save_quarantine_records(self.blocked_threats)
        self.log(f"File permanently deleted: {record.get('filename')}")
        self.show_frame("issues")

    def empty_quarantine(self):
        if not self.blocked_threats:
            return
        if not messagebox.askyesno(APP_NAME, "Permanently delete ALL files in quarantine?"):
            return
        for record in list(self.blocked_threats):
            source = record.get("quarantine_path")
            try:
                if source and os.path.exists(source):
                    os.remove(source)
            except OSError:
                pass
        self.blocked_threats = []
        save_quarantine_records(self.blocked_threats)
        self.log("Quarantine emptied by user.")
        self.show_frame("issues")

    # ------------------------------------------------------------------- #
    # Tab: Settings (new)
    # ------------------------------------------------------------------- #
    def build_settings(self):
        c = self.colors
        tk.Label(self.content_frame, text="Settings", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 20))

        # Theme
        theme_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        theme_frame.pack(fill="x", pady=6)
        tk.Label(theme_frame, text="Visual theme", bg=c["bg_card"], fg=c["fg_text"], font=("Arial", 14)).pack(side="left")
        tk.Button(theme_frame, text="Toggle light/dark", command=self.toggle_theme, bg="white", fg="black",
                  bd=0, padx=10, pady=4, cursor="hand2").pack(side="right")

        # Exclusions
        excl_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        excl_frame.pack(fill="x", pady=6)
        tk.Label(excl_frame, text="Folders excluded from scanning:", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 14)).pack(anchor="w")
        self.excl_listbox = tk.Listbox(excl_frame, height=4, font=("Consolas", 10))
        self.excl_listbox.pack(fill="x", pady=5)
        for e in self.config.get("exclusions", []):
            self.excl_listbox.insert("end", e)
        btns = tk.Frame(excl_frame, bg=c["bg_card"])
        btns.pack(anchor="e")
        tk.Button(btns, text="Add folder", command=self.add_exclusion, bg="white", fg="black",
                  bd=0, padx=8, cursor="hand2").pack(side="left", padx=4)
        tk.Button(btns, text="Remove selected", command=self.remove_exclusion, bg="white", fg="black",
                  bd=0, padx=8, cursor="hand2").pack(side="left", padx=4)

        # Signatures
        sig_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        sig_frame.pack(fill="x", pady=6)
        tk.Label(sig_frame, text=f"Loaded signatures: {len(self.signatures)}", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 14)).pack(side="left")
        tk.Button(sig_frame, text="Import signatures (JSON)", command=self.import_signatures, bg="white",
                  fg="black", bd=0, padx=10, pady=4, cursor="hand2").pack(side="right")

        # Max file size
        size_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        size_frame.pack(fill="x", pady=6)
        tk.Label(size_frame, text="Maximum file size to analyze (MB):", bg=c["bg_card"],
                  fg=c["fg_text"], font=("Arial", 14)).pack(side="left")
        self.max_size_var = tk.IntVar(value=self.config.get("max_hash_size_mb", 200))
        tk.Spinbox(size_frame, from_=10, to=5000, increment=10, textvariable=self.max_size_var,
                   width=8, command=self.save_max_size).pack(side="right")

        # Other actions
        actions_frame = tk.Frame(self.content_frame, bg=c["bg_main"])
        actions_frame.pack(fill="x", pady=15)
        tk.Button(actions_frame, text="Clear logs", command=self.clear_logs, bg=c["bg_card"], fg="white",
                  bd=0, padx=10, pady=6, cursor="hand2").pack(side="left", padx=5)
        tk.Button(actions_frame, text="Reset configuration", command=self.reset_config, bg=c["accent_warn"],
                  fg="white", bd=0, padx=10, pady=6, cursor="hand2").pack(side="left", padx=5)

    def toggle_theme(self):
        self.config["theme"] = "dark" if self.config.get("theme") == "light" else "light"
        save_config(self.config)
        self.build_ui()
        self.show_frame("settings")

    def add_exclusion(self):
        folder = filedialog.askdirectory(title="Select folder to exclude from scanning")
        if folder:
            exclusions = self.config.setdefault("exclusions", [])
            if folder not in exclusions:
                exclusions.append(folder)
                save_config(self.config)
                self.excl_listbox.insert("end", folder)

    def remove_exclusion(self):
        sel = self.excl_listbox.curselection()
        if not sel:
            return
        value = self.excl_listbox.get(sel[0])
        exclusions = self.config.get("exclusions", [])
        if value in exclusions:
            exclusions.remove(value)
            save_config(self.config)
        self.excl_listbox.delete(sel[0])

    def import_signatures(self):
        path = filedialog.askopenfilename(title="Select signatures JSON file",
                                           filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            self.signatures, added = merge_signatures_from_file(path)
            messagebox.showinfo(APP_NAME, f"Imported {added} new signature(s).")
            self.show_frame("settings")
        except (OSError, json.JSONDecodeError, KeyError) as e:
            messagebox.showerror(APP_NAME, f"Could not import the signatures file: {e}")

    def save_max_size(self):
        self.config["max_hash_size_mb"] = self.max_size_var.get()
        save_config(self.config)

    def clear_logs(self):
        if messagebox.askyesno(APP_NAME, "Clear the on-screen log history?"):
            self.log_buffer.clear()
            self.show_frame("security")

    def reset_config(self):
        if messagebox.askyesno(APP_NAME, "Reset all configuration to defaults?"):
            self.config = default_config()
            save_config(self.config)
            self.build_ui()

    # ------------------------------------------------------------------- #
    # Real-time protection logic
    # ------------------------------------------------------------------- #
    def _refresh_status_indicator(self):
        color = self.colors["accent_ok"] if self.monitoring else self.colors["accent_warn"]
        text = "Protected" if self.monitoring else "Unprotected"
        self.status_canvas.itemconfig(self.status_dot, fill=color)
        self.status_label.config(text=text)

    def toggle_autoprotection(self):
        self.config["autoprotection"] = self.autoprotection_active.get()
        save_config(self.config)
        if self.autoprotection_active.get():
            with self.state_lock:
                self.monitoring = True
            messagebox.showinfo(APP_NAME, "Automatic protection ENABLED.\nMonitoring processes in the background.")
        else:
            with self.state_lock:
                self.monitoring = False
            messagebox.showwarning(APP_NAME, "Automatic protection DISABLED.")
        self._refresh_status_indicator()

    def log(self, message: str):
        self.logger.info(message)
        self.log_buffer.append(message)
        try:
            self.root.after(0, self._update_log, message)
        except RuntimeError:
            pass  # window already closed

    def _update_log(self, message: str):
        # Improvement: validates that the widget exists before writing (prevents
        # crashing if the user switches tabs right when a message arrives from the thread).
        if not hasattr(self, "log_text") or not self.log_text.winfo_exists():
            return
        self.log_text.config(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _set_scan_buttons_state(self, state: str):
        for btn in (getattr(self, "btn_quick", None), getattr(self, "btn_full", None),
                    getattr(self, "btn_custom", None)):
            if btn is not None and btn.winfo_exists():
                btn.config(state=state)
        if hasattr(self, "btn_stop") and self.btn_stop.winfo_exists():
            self.btn_stop.config(state="normal" if state == "disabled" else "disabled")

    def stop_scan(self):
        self.scan_cancel_event.set()
        self.log("Cancellation requested by user...")

    def start_scan(self, scan_type: str, custom_path: Optional[str] = None):
        if self.scan_running:
            messagebox.showwarning(APP_NAME, "A scan is already in progress.")
            return
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, "end")
        self.log_text.config(state="disabled")
        self.log_buffer.clear()

        self.scan_cancel_event.clear()
        self.scan_running = True
        self._set_scan_buttons_state("disabled")
        if hasattr(self, "progress"):
            self.progress.start(15)
        threading.Thread(target=self.run_real_scan, args=(scan_type, custom_path), daemon=True).start()

    def run_real_scan(self, scan_type: str, custom_path: Optional[str] = None):
        try:
            self._run_real_scan_inner(scan_type, custom_path)
        except Exception as e:  # Improvement: an unexpected error no longer kills the thread silently
            self.log(f"[Unexpected error during scan] {e}")
            self.logger.exception("Unexpected error during scan")
        finally:
            self.scan_running = False
            self.root.after(0, self._on_scan_finished)

    def _on_scan_finished(self):
        self._set_scan_buttons_state("normal")
        if hasattr(self, "progress") and self.progress.winfo_exists():
            self.progress.stop()

    def _run_real_scan_inner(self, scan_type: str, custom_path: Optional[str] = None):
        start = time.time()
        self.log(f"Starting {scan_type} scan...")
        time.sleep(0.3)

        user_home = os.path.expanduser("~")
        if custom_path:
            paths = [custom_path]
        elif scan_type == "Quick":
            paths = [os.path.join(user_home, "Downloads"), os.path.join(user_home, "Desktop")]
            if platform.system() == "Windows":
                paths.append(os.environ.get("TEMP", "C:\\Temp"))
            else:
                paths.append(tempfile.gettempdir())
        else:
            paths = [user_home]

        exclusions = self.config.get("exclusions", [])
        max_size_bytes = self.config.get("max_hash_size_mb", 200) * 1024 * 1024

        scanned_files = 0
        threats_found = 0
        skipped_large = 0
        errors = 0
        canceled = False
        last_update = time.time()

        for path in paths:
            if not os.path.exists(path):
                continue
            self.log(f"Scanning: {path}...")

            for root_dir, dirs, files in os.walk(path, followlinks=False):
                if self.scan_cancel_event.is_set():
                    canceled = True
                    break
                # Improvement: excluded folders are pruned before entering (faster
                # and avoids permission errors on system folders)
                dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root_dir, d), exclusions)]

                for file in files:
                    if self.scan_cancel_event.is_set():
                        canceled = True
                        break
                    filepath = os.path.join(root_dir, file)
                    scanned_files += 1

                    try:
                        hashes = compute_hashes(filepath, max_size_bytes)
                        if hashes is None:
                            if os.path.exists(filepath) and os.path.getsize(filepath) > max_size_bytes:
                                skipped_large += 1
                            else:
                                errors += 1
                        else:
                            malware_name = match_signature(hashes, self.signatures)
                            if malware_name:
                                self.log(f"ALERT! Malware detected: {file}")
                                self.log(f"Signature: {malware_name}")
                                record = self._quarantine_file(filepath, malware_name, hashes)
                                if record:
                                    self.log("File successfully quarantined.")
                                    threats_found += 1
                                else:
                                    self.log(f"Error moving to quarantine: {file}")

                        if file.lower().endswith(SUSPICIOUS_DOUBLE_EXTENSIONS):
                            self.log(f"ALERT! File with suspicious double extension: {file}")
                            record = self._quarantine_file(filepath, "Double Extension", hashes or {})
                            if record:
                                threats_found += 1
                    except Exception:
                        errors += 1  # a problematic file must not bring down the whole scan

                    if scanned_files % 100 == 0 and time.time() - last_update > 0.3:
                        self.log(f"Files analyzed: {scanned_files}...")
                        last_update = time.time()

                if canceled:
                    break
            if canceled:
                break

        duration = round(time.time() - start, 1)
        self.log("----------------------------------------")
        if canceled:
            self.log(f"{scan_type} scan CANCELED by user.")
        else:
            self.log(f"{scan_type} scan finished.")
        self.log(f"Files scanned: {scanned_files}")
        self.log(f"Threats neutralized: {threats_found}")
        if skipped_large:
            self.log(f"Files skipped due to size: {skipped_large}")
        if errors:
            self.log(f"Files with read/permission errors: {errors}")
        self.log(f"Duration: {duration} s")

        if threats_found == 0 and not canceled:
            self.log("The system is clean.")

        summary = {"type": scan_type, "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                   "scanned": scanned_files, "threats": threats_found,
                   "duration_sec": duration, "canceled": canceled}
        self.config["last_scan"] = summary
        history = self.config.setdefault("scan_history", [])
        history.append(summary)
        self.config["scan_history"] = history[-20:]  # keeps only the last 20
        save_config(self.config)

        if not canceled:
            self.root.after(0, lambda: messagebox.showinfo(
                APP_NAME, f"{scan_type} scan completed.\nThreats found: {threats_found}"))

    def _quarantine_file(self, filepath: str, threat_name: str, hashes: dict) -> Optional[dict]:
        """Moves the file and saves metadata so it can be restored later."""
        original_path = filepath
        dest = quarantine_move(filepath, self.quarantine_dir)
        if not dest:
            return None
        record = {
            "id": uuid.uuid4().hex,
            "filename": os.path.basename(filepath),
            "original_path": original_path,
            "quarantine_path": dest,
            "threat_name": threat_name,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "sha256": hashes.get("sha256", ""),
        }
        with self.state_lock:
            self.blocked_threats.append(record)
            save_quarantine_records(self.blocked_threats)
        return record

    def background_monitor(self):
        """Real-time monitoring of suspicious processes (daemon thread,
        but now it can be stopped cleanly with monitor_stop_event)."""
        suspicious_processes = set(DEFAULT_SUSPICIOUS_PROCESSES) - set(self.config.get("process_whitelist", []))
        last_alert = 0.0

        while not self.monitor_stop_event.is_set():
            if self.monitoring and psutil:
                for proc in psutil.process_iter(["name"]):
                    try:
                        proc_name = (proc.info["name"] or "").lower()
                        if proc_name in suspicious_processes and time.time() - last_alert > 10:
                            self.log(f"REAL-TIME BLOCK! Suspicious process detected: {proc_name}")
                            self.root.after(0, lambda p=proc_name: messagebox.showwarning(
                                APP_NAME, f"Real-time threat!\nSuspicious process detected: {p}"))
                            last_alert = time.time()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
            self.monitor_stop_event.wait(self.config.get("monitor_interval_seconds", 5))

    # ------------------------------------------------------------------- #
    # Application shutdown
    # ------------------------------------------------------------------- #
    def on_close(self):
        if self.scan_running and not messagebox.askyesno(
                APP_NAME, "A scan is in progress. Do you want to close anyway?"):
            return
        self.scan_cancel_event.set()
        self.monitor_stop_event.set()
        self.config["window_geometry"] = self.root.geometry()
        save_config(self.config)
        self.root.destroy()


# --------------------------------------------------------------------------- #
# CLI mode (no GUI) — useful for automating scans
# --------------------------------------------------------------------------- #
def run_cli_scan(scan_type: str, custom_path: Optional[str], logger: logging.Logger) -> int:
    ensure_app_dirs()
    config = load_config()
    signatures = load_signatures()
    exclusions = config.get("exclusions", [])
    max_size_bytes = config.get("max_hash_size_mb", 200) * 1024 * 1024
    quarantine_records = load_quarantine_records()

    user_home = os.path.expanduser("~")
    if custom_path:
        paths = [custom_path]
    elif scan_type == "quick":
        paths = [os.path.join(user_home, "Downloads"), os.path.join(user_home, "Desktop")]
    else:
        paths = [user_home]

    print(f"{APP_NAME} v{APP_VERSION} — CLI scan ({scan_type})")
    files, threats = 0, 0
    start = time.time()

    for path in paths:
        if not os.path.exists(path):
            continue
        for root_dir, dirs, files_list in os.walk(path, followlinks=False):
            dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root_dir, d), exclusions)]
            for file in files_list:
                filepath = os.path.join(root_dir, file)
                files += 1
                hashes = compute_hashes(filepath, max_size_bytes)
                name = match_signature(hashes, signatures) if hashes else None
                # Improvement: the double-extension heuristic now also runs in
                # CLI mode (previously it only existed in the GUI, inconsistent behavior)
                if not name and file.lower().endswith(SUSPICIOUS_DOUBLE_EXTENSIONS):
                    name = "Double Extension"
                if name:
                    dest = quarantine_move(filepath, QUARANTINE_DIR)
                    if dest:
                        quarantine_records.append({
                            "id": uuid.uuid4().hex, "filename": file, "original_path": filepath,
                            "quarantine_path": dest, "threat_name": name,
                            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "sha256": (hashes or {}).get("sha256", ""),
                        })
                        threats += 1
                        print(f"  [!] {file} -> {name} (quarantine)")
                        logger.info(f"CLI: {file} -> {name} (quarantine)")
                if files % 500 == 0:
                    print(f"  ... {files} files analyzed")

    save_quarantine_records(quarantine_records)
    duration = round(time.time() - start, 1)
    config["last_scan"] = {"type": scan_type, "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "scanned": files, "threats": threats, "duration_sec": duration,
                            "canceled": False}
    save_config(config)
    print(f"Done. Files: {files} | Threats: {threats} | Duration: {duration}s")
    return 0


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--scan", choices=["quick", "full"],
                         help="Runs a scan without opening the graphical interface")
    parser.add_argument("--path", help="Custom path to scan in CLI mode")
    args = parser.parse_args()

    ensure_app_dirs()
    logger = setup_logger()

    if args.scan:
        sys.exit(run_cli_scan(args.scan, args.path, logger))

    root = tk.Tk()
    app = DavidSecureApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
