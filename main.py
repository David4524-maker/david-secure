"""
David Secure - Antivirus Engine
================================
v5.0.3 — Mensajes honestos de log + logo simplificado (sin la V naranja).
Proyecto educativo / de portafolio.

Modo GUI:   python david_secure.py
Modo CLI:   python david_secure.py --scan rapido
            python david_secure.py --scan completo --path "/ruta" --json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import html as html_lib
import json
import logging
import logging.handlers
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import uuid
import zipfile
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Optional

try:
    import psutil
except ImportError:
    psutil = None


# --------------------------------------------------------------------------- #
# Constantes y rutas
# --------------------------------------------------------------------------- #
APP_NAME = "David Secure"
APP_VERSION = "5.0.3"

APP_DIR = Path.home() / ".david_secure"
CONFIG_PATH = APP_DIR / "config.json"
CONFIG_BACKUP_PATH = APP_DIR / "config.backup.json"
QUARANTINE_META_PATH = APP_DIR / "quarantine_meta.json"
SIGNATURES_PATH = APP_DIR / "signatures.json"
SIGNATURES_BACKUP_PATH = APP_DIR / "signatures.backup.json"
SCAN_CACHE_PATH = APP_DIR / "scan_cache.json"
SCAN_PROFILES_PATH = APP_DIR / "scan_profiles.json"
PLUGINS_DIR = APP_DIR / "plugins"
LOG_DIR = APP_DIR / "logs"
QUARANTINE_DIR = Path.home() / "DavidSecure_Quarantine"
LOCK_PATH = APP_DIR / "app.lock"

DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv",
    "$RECYCLE.BIN", "System Volume Information", ".Trash",
}
DOUBLE_EXT_SOSPECHOSAS = (
    ".pdf.exe", ".docx.exe", ".jpg.exe", ".txt.exe", ".png.exe",
    ".xlsx.exe", ".zip.exe", ".mp3.exe", ".pptx.exe",
)
PROCESOS_SOSPECHOSOS_DEFAULT = ["mimikatz.exe", "nc.exe", "netcat.exe", "keylogger.exe"]

HASH_BUFFER_SIZE = 65536
QUARANTINE_XOR_KEY = 0x5A
ARGUMENTOS_SOSPECHOSOS = {"sekurlsa::", "lsadump::", "-lvp", "-le", "exec cmd.exe"}

EXEC_EXTS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
             ".js", ".jse", ".wsf", ".ps1", ".hta", ".jar", ".msi"}
SCRIPT_PATTERNS = [
    (re.compile(rb"Invoke-Expression\s*\(", re.I), "PowerShell.InvokeExpression"),
    (re.compile(rb"IEX\s*\(", re.I), "PowerShell.IEX"),
    (re.compile(rb"DownloadString\s*\(", re.I), "PowerShell.DownloadString"),
    (re.compile(rb"FromBase64String", re.I), "PowerShell.Base64Decode"),
    (re.compile(rb"WScript\.Shell", re.I), "Script.WScriptShell"),
    (re.compile(rb"CreateObject\s*\(\s*[\"']WScript", re.I), "Script.WScriptCreateObject"),
    (re.compile(rb"eval\s*\(\s*base64_decode", re.I), "PHP.EvalBase64"),
    (re.compile(rb"document\.write\s*\(\s*unescape", re.I), "JS.UnescapeWrite"),
]
HEADER_PATTERNS = [
    (b"MZ", "PE/EXE"),
    (b"\x7fELF", "ELF"),
    (b"PK\x03\x04", "ZIP"),
]
ARCHIVE_EXTS = {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx"}

HASH_WHITELIST_PATH = APP_DIR / "hash_whitelist.json"

TRANSLATIONS = {
    "es": {
        "menu_info": "Info", "menu_seguridad": "Seguridad", "menu_cuentas": "Cuentas",
        "menu_dispositivo": "Dispositivo", "menu_problemas": "Problemas",
        "menu_config": "Configuración", "menu_historial": "Historial",
        "btn_quick": "Rápido", "btn_full": "Completo", "btn_custom": "Personalizado",
        "btn_stop": "Detener escaneo", "status_protected": "Protegido",
        "status_unprotected": "Desprotegido", "scan_running": "Escaneando...",
    },
    "en": {
        "menu_info": "Info", "menu_seguridad": "Security", "menu_cuentas": "Accounts",
        "menu_dispositivo": "Device", "menu_problemas": "Issues",
        "menu_config": "Settings", "menu_historial": "History",
        "btn_quick": "Quick", "btn_full": "Full", "btn_custom": "Custom",
        "btn_stop": "Stop scan", "status_protected": "Protected",
        "status_unprotected": "Unprotected", "scan_running": "Scanning...",
    },
}

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
# Utilidades puras
# --------------------------------------------------------------------------- #
def ensure_app_dirs() -> None:
    for d in (APP_DIR, LOG_DIR, QUARANTINE_DIR, PLUGINS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def setup_logger(level: int = logging.INFO, json_format: bool = False) -> logging.Logger:
    logger = logging.getLogger("david_secure")
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "david_secure.log", maxBytes=2 * 1024 * 1024,
        backupCount=3, encoding="utf-8"
    )
    if json_format:
        fmt = logging.Formatter('{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":%(message)s}')
    else:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger


def human_readable_size(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def load_json(path: Path, default):
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return default


def save_json(path: Path, data) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent))
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        return True
    except OSError:
        return False


def save_json_with_backup(path: Path, backup_path: Path, data) -> bool:
    if path.exists():
        try:
            shutil.copy2(path, backup_path)
        except OSError:
            pass
    return save_json(path, data)


def load_config_with_migration() -> dict:
    cfg = default_config()
    loaded = load_json(CONFIG_PATH, None)
    if loaded is None:
        loaded = load_json(CONFIG_BACKUP_PATH, {})
    if isinstance(loaded, dict):
        for k in list(loaded.keys()):
            if k in cfg:
                cfg[k] = loaded[k]
        cfg["_version"] = APP_VERSION
    return cfg


def default_config() -> dict:
    return {
        "theme": "light",
        "autoproteccion": False,
        "exclusions": [],
        "exclusion_patterns": [],
        "max_hash_size_mb": 200,
        "monitor_interval_seconds": 5,
        "process_whitelist": [],
        "last_scan": None,
        "scan_history": [],
        "window_geometry": "1100x650",
        "language": "es",
        "log_json": False,
        "log_level": "INFO",
        "scan_threads": 4,
        "scan_throttle_ms": 0,
        "battery_aware": True,
        "incremental": True,
        "shutdown_after_scan": False,
        "deep_archives": True,
        "password_hash": None,
        "hash_whitelist": [],
        "scheduled_scan": None,
        "self_integrity": True,
        "entropy_threshold": 7.2,
        "notify_on_threat": True,
        "quarantine_password": None,
        "_version": APP_VERSION,
    }


def load_config() -> dict:
    return load_config_with_migration()


def save_config(config: dict) -> None:
    save_json_with_backup(CONFIG_PATH, CONFIG_BACKUP_PATH, config)


def default_signatures() -> list:
    return [
        {"hash": "44d88612fea8a8f36de82e1278abb02f", "algo": "md5",
         "name": "EICAR Test File (archivo estándar de prueba, no es un virus real)",
         "severity": "test"},
        {"hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0",
         "algo": "sha256",
         "name": "EICAR Test File (archivo estándar de prueba, no es un virus real)",
         "severity": "test"},
        {"hash": "5d41402abc4b2a76b9719d911017c592", "algo": "md5",
         "name": "Malware.Simulado.1", "severity": "medium"},
        {"hash": "7d793037a0760186574b0282f2f435e7", "algo": "md5",
         "name": "Trojan.Generic.Test", "severity": "high"},
    ]


def load_signatures() -> list:
    sigs = load_json(SIGNATURES_PATH, None)
    if not sigs:
        sigs = load_json(SIGNATURES_BACKUP_PATH, None)
    if not sigs:
        sigs = default_signatures()
        save_json_with_backup(SIGNATURES_PATH, SIGNATURES_BACKUP_PATH, sigs)
    return sigs


def merge_signatures_from_file(path: str) -> tuple[list, int]:
    current = load_signatures()
    existing = {(s["hash"].lower(), s["algo"]) for s in current}
    with open(path, "r", encoding="utf-8") as f:
        nuevas = json.load(f)
    agregadas = 0
    for sig in nuevas:
        key = (sig.get("hash", "").lower(), sig.get("algo", "sha256"))
        if key[0] and key not in existing:
            current.append({
                "hash": key[0], "algo": key[1],
                "name": sig.get("name", "Firma sin nombre"),
                "severity": sig.get("severity", "unknown"),
            })
            existing.add(key)
            agregadas += 1
    save_json_with_backup(SIGNATURES_PATH, SIGNATURES_BACKUP_PATH, current)
    return current, agregadas


def update_signatures_from_url(url: str, timeout: int = 15) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        return 0, f"Error: {e}"
    current = load_signatures()
    existing = {(s["hash"].lower(), s["algo"]) for s in current}
    added = 0
    for sig in data:
        key = (sig.get("hash", "").lower(), sig.get("algo", "sha256"))
        if key[0] and key not in existing:
            current.append({"hash": key[0], "algo": key[1],
                            "name": sig.get("name", "Firma externa"),
                            "severity": sig.get("severity", "unknown")})
            existing.add(key)
            added += 1
    save_json_with_backup(SIGNATURES_PATH, SIGNATURES_BACKUP_PATH, current)
    return added, "OK"


def load_quarantine_records() -> list:
    return load_json(QUARANTINE_META_PATH, [])


def save_quarantine_records(records: list) -> None:
    save_json(QUARANTINE_META_PATH, records)


def load_hash_whitelist() -> set:
    return set(h.lower() for h in load_json(HASH_WHITELIST_PATH, []))


def save_hash_whitelist(hashes: set) -> None:
    save_json(HASH_WHITELIST_PATH, sorted(hashes))


def compute_hashes(filepath: str, max_size_bytes: Optional[int] = None) -> Optional[dict]:
    try:
        if max_size_bytes is not None and os.path.getsize(filepath) > max_size_bytes:
            return None
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            buf = f.read(HASH_BUFFER_SIZE)
            while buf:
                md5.update(buf)
                sha1.update(buf)
                sha256.update(buf)
                buf = f.read(HASH_BUFFER_SIZE)
        return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest()}
    except (PermissionError, FileNotFoundError, OSError):
        return None


def match_signature(hashes: dict, signatures: list) -> Optional[dict]:
    for sig in signatures:
        valor = hashes.get(sig["algo"])
        if valor and valor.lower() == sig["hash"].lower():
            return {"name": sig.get("name", "Unknown"),
                    "severity": sig.get("severity", "unknown"),
                    "source": "signature"}
    return None


def calculate_entropy(filepath: str, sample_size: int = 65536) -> float:
    try:
        with open(filepath, "rb") as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for c in counts.values():
            p = c / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)
    except OSError:
        return 0.0


def detect_script_patterns(filepath: str, sample_size: int = 65536) -> Optional[str]:
    try:
        with open(filepath, "rb") as f:
            data = f.read(sample_size)
        for pattern, name in SCRIPT_PATTERNS:
            if pattern.search(data):
                return name
    except OSError:
        pass
    return None


def is_executable_content(filepath: str) -> Optional[str]:
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
        for marker, name in HEADER_PATTERNS:
            if header.startswith(marker):
                return name
    except OSError:
        pass
    return None


def inspect_archive(filepath: str, max_entries: int = 50) -> Optional[list]:
    if not zipfile.is_zipfile(filepath):
        return None
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            names = z.namelist()[:max_entries]
        sospechosos = [n for n in names
                       if n.lower().endswith((".exe", ".dll", ".scr", ".bat", ".vbs"))]
        return sospechosos or None
    except (zipfile.BadZipFile, OSError):
        return None


def load_scan_cache() -> dict:
    return load_json(SCAN_CACHE_PATH, {})


def save_scan_cache(cache: dict) -> None:
    cutoff = (datetime.now() - timedelta(days=60)).timestamp()
    cache = {k: v for k, v in cache.items() if v.get("ts", 0) > cutoff}
    save_json(SCAN_CACHE_PATH, cache)


def file_cache_key(path: str, size: int, mtime: float) -> str:
    return f"{path}|{size}|{int(mtime)}"


def is_excluded(dirpath: str, exclusions: list, patterns: Optional[list] = None) -> bool:
    import fnmatch
    base = os.path.basename(dirpath)
    if base in DEFAULT_EXCLUDED_DIRS:
        return True
    normalized = os.path.normcase(os.path.abspath(dirpath))
    for excl in exclusions:
        try:
            if normalized.startswith(os.path.normcase(os.path.abspath(excl))):
                return True
        except (OSError, ValueError):
            continue
    if patterns:
        for pat in patterns:
            if fnmatch.fnmatch(base, pat) or fnmatch.fnmatch(normalized, pat):
                return True
    return False


def quarantine_move(filepath: str, quarantine_dir: Path,
                    password: Optional[str] = None) -> Optional[tuple[str, bytes]]:
    try:
        filename = os.path.basename(filepath)
        dest = quarantine_dir / f"{filename}.locked"
        if dest.exists():
            stem, _ = os.path.splitext(filename)
            dest = quarantine_dir / f"{stem}_{uuid.uuid4().hex[:8]}.locked"

        with open(filepath, "rb") as f_in:
            data = f_in.read()

        salt = os.urandom(16)
        if password:
            key_bytes = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 50000)
        else:
            key_bytes = bytes([QUARANTINE_XOR_KEY])
        key_len = len(key_bytes)
        encrypted = bytearray(b ^ key_bytes[i % key_len] for i, b in enumerate(data))

        with open(dest, "wb") as f_out:
            f_out.write(salt)
            f_out.write(encrypted)
        os.remove(filepath)
        try:
            with open(filepath, "wb") as f:
                f.write(os.urandom(min(len(data), 4096)))
        except OSError:
            pass
        os.chmod(str(dest), 0o600)
        return str(dest), salt
    except OSError:
        return None


def open_folder_in_explorer(path: str) -> None:
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


def send_notification(title: str, message: str) -> None:
    try:
        system = platform.system()
        if system == "Linux" and shutil.which("notify-send"):
            subprocess.Popen(["notify-send", title, message])
        elif system == "Darwin" and shutil.which("osascript"):
            subprocess.Popen(["osascript", "-e",
                              f'display notification "{message}" with title "{title}"'])
        elif system == "Windows" and shutil.which("powershell"):
            script = (f'[reflection.assembly]::loadwithpartialname("System.Windows.Forms")|'
                      f'Out-Null;$n=New-Object System.Windows.Forms.NotifyIcon;'
                      f'$n.Icon=[System.Drawing.SystemIcons]::Information;'
                      f'$n.Visible=$true;$n.ShowBalloonTip(3000,"{title}","{message}",0)')
            subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", script])
    except OSError:
        pass


def self_integrity_check() -> tuple[bool, str]:
    try:
        own = Path(__file__).resolve()
        h = hashlib.sha256(own.read_bytes()).hexdigest()
        store = APP_DIR / "self.hash"
        if store.exists():
            prev = store.read_text().strip()
            if prev != h:
                store.write_text(h)
                return True, "Cambio detectado (actualizado)."
        else:
            store.write_text(h)
        return True, "OK"
    except OSError as e:
        return False, str(e)


def acquire_lock() -> bool:
    try:
        if LOCK_PATH.exists():
            try:
                pid = int(LOCK_PATH.read_text().strip())
                if psutil and psutil.pid_exists(pid):
                    return False
            except (ValueError, OSError):
                pass
        LOCK_PATH.write_text(str(os.getpid()))
        return True
    except OSError:
        return True


def release_lock() -> None:
    try:
        if LOCK_PATH.exists():
            LOCK_PATH.unlink()
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Tooltip
# --------------------------------------------------------------------------- #
class ToolTip:
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
# Aplicación principal
# --------------------------------------------------------------------------- #
class DavidSecureApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        ensure_app_dirs()

        cfg = load_config()
        log_level = getattr(logging, cfg.get("log_level", "INFO"), logging.INFO)
        self.logger = setup_logger(log_level, json_format=cfg.get("log_json", False))

        self.config = cfg
        self.signatures = load_signatures()
        self.hash_whitelist = load_hash_whitelist()
        self.scan_cache = load_scan_cache()
        self.quarantine_dir = QUARANTINE_DIR

        if self.config.get("self_integrity", True):
            ok, msg = self_integrity_check()
            if not ok:
                messagebox.showwarning(APP_NAME, f"Auto-integridad: {msg}")

        self.autoproteccion_activa = tk.BooleanVar(value=self.config.get("autoproteccion", False))
        self.amenazas_bloqueadas = load_quarantine_records()
        self.log_buffer: list[str] = []
        self.filter_var = tk.StringVar(value="")

        self.state_lock = threading.Lock()
        self.monitoring = self.autoproteccion_activa.get()
        self.monitor_stop_event = threading.Event()
        self.scan_cancel_event = threading.Event()
        self.scan_pause_event = threading.Event()
        self.scan_pause_event.set()
        self.scan_running = False
        self.scan_start_time = 0.0
        self.scan_files_total_estimate = 0
        self.current_lang = self.config.get("language", "es")
        self._closing = False

        self.root.title(f"{APP_NAME} - Antivirus Engine  v{APP_VERSION}")
        self.root.geometry(self.config.get("window_geometry", "1100x650"))
        self.root.minsize(900, 550)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.root.bind("<F5>", lambda e: self.start_scan("Rápido"))
        self.root.bind("<F6>", lambda e: self.start_scan("Completo"))
        self.root.bind("<Control-q>", lambda e: self.on_close())
        self.root.bind("<Control-p>", lambda e: self.toggle_pause())
        self.root.bind("<F1>", lambda e: self.show_shortcuts())

        self.plugins = self._load_plugins()

        self.build_ui()

        if psutil is None:
            self.log("[Aviso] psutil no instalado: monitoreo de procesos deshabilitado.")
        else:
            threading.Thread(target=self.background_monitor, daemon=True).start()

        self._schedule_next_scan()
        self._autosave_loop()

    # ------------------------------------------------------------------- #
    # Plugins
    # ------------------------------------------------------------------- #
    def _load_plugins(self) -> list:
        plugins = []
        if not PLUGINS_DIR.exists():
            return plugins
        import importlib.util
        for py_file in PLUGINS_DIR.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "scan") and callable(mod.scan):
                    plugins.append((py_file.stem, mod.scan))
            except Exception as e:
                self.logger.warning(f"Plugin {py_file.name} falló: {e}")
        return plugins

    def _autosave_loop(self):
        def loop():
            while not getattr(self, "_closing", False):
                time.sleep(300)
                try:
                    save_config(self.config)
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True).start()

    # ------------------------------------------------------------------- #
    # UI
    # ------------------------------------------------------------------- #
    def t(self, key: str) -> str:
        return TRANSLATIONS.get(self.current_lang, TRANSLATIONS["es"]).get(key, key)

    def build_ui(self):
        self.colors = THEMES[self.config.get("theme", "light")]
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.configure(bg=self.colors["bg_main"])

        self.left_frame = tk.Frame(self.root, bg=self.colors["bg_nav"], width=300)
        self.left_frame.pack(side="left", fill="y")
        self.left_frame.pack_propagate(False)

        self.logo_canvas = tk.Canvas(self.left_frame, width=280, height=100,
                                      bg=self.colors["bg_nav"], highlightthickness=0)
        self.logo_canvas.pack(pady=(20, 0))
        self._draw_logo(self.logo_canvas, canvas_width=280, canvas_height=100)

        status_frame = tk.Frame(self.left_frame, bg=self.colors["bg_nav"])
        status_frame.pack(pady=(0, 10))
        self.status_canvas = tk.Canvas(status_frame, width=16, height=16,
                                        bg=self.colors["bg_nav"], highlightthickness=0)
        self.status_canvas.pack(side="left", padx=(0, 6))
        self.status_dot = self.status_canvas.create_oval(2, 2, 14, 14, fill="#FF4D4D", outline="")
        self.status_label = tk.Label(status_frame, text=self.t("status_unprotected"),
                                      bg=self.colors["bg_nav"],
                                      fg=self.colors["fg_text"], font=("Arial", 10))
        self.status_label.pack(side="left")
        self._refresh_status_indicator()

        btn_style = {"bg": self.colors["bg_nav"], "fg": "white", "font": ("Arial", 15),
                     "bd": 0, "anchor": "w", "padx": 20, "cursor": "hand2"}

        nav_items = [
            (f"{self.t('menu_info')}  ⓘ", "info", self.colors["accent_info"]),
            (f"{self.t('menu_seguridad')}  🛡️", "seguridad", self.colors["accent_seg"]),
            (f"{self.t('menu_cuentas')}  👤", "cuentas", self.colors["accent_ok"]),
            (f"{self.t('menu_dispositivo')}  🖥️", "dispositivo", "#B3B3B3"),
            (f"{self.t('menu_problemas')}  ❗", "problemas", self.colors["accent_warn"]),
            (f"{self.t('menu_historial')}  📊", "historial", "#A0E0FF"),
            (f"{self.t('menu_config')}  ⚙️", "configuracion", "#CCCCCC"),
        ]
        for texto, frame_name, color in nav_items:
            b = tk.Button(self.left_frame, text=texto,
                          command=lambda f=frame_name: self.show_frame(f), **btn_style)
            b.configure(fg=color)
            b.pack(fill="x", pady=6)

        version_lbl = tk.Label(self.left_frame, text=f"v{APP_VERSION}", bg=self.colors["bg_nav"],
                                fg="#8888AA", font=("Arial", 9))
        version_lbl.pack(side="bottom", pady=10)

        self.status_bar = tk.Label(self.root, text="Listo", bd=1, relief="sunken",
                                    anchor="w", bg=self.colors["bg_nav"], fg="white")
        self.status_bar.pack(side="bottom", fill="x")

        self.right_frame = tk.Frame(self.root, bg=self.colors["bg_main"])
        self.right_frame.pack(side="right", fill="both", expand=True)
        self.content_frame = tk.Frame(self.right_frame, bg=self.colors["bg_main"])
        self.content_frame.pack(fill="both", expand=True, padx=30, pady=20)

        self.show_frame("seguridad")

    def _draw_logo(self, canvas: tk.Canvas, canvas_width: int, canvas_height: int):
        """Dibuja el ícono (D roja + cuadro amarillo) y el texto 'David Secure'.
        Ya no incluye la 'V' naranja que solía ir encima."""
        import tkinter.font as tkfont
        icon_w, icon_h = 40, 60
        gap_icon_text = 14
        gap_words = 7
        padding = 8
        available_width = canvas_width - 2 * padding

        font_size = 28
        min_font_size = 15
        w_david = w_secure = 0
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
        ix, iy = start_x, (canvas_height - icon_h) / 2
        text_y = canvas_height / 2

        def m(x, y):
            return (ix + (x - 30), iy + (y - 20))

        # Ícono: solo las dos formas base (rojo + amarillo).
        # La 'V' naranja fue eliminada para simplificar el logo.
        canvas.create_polygon(*m(30, 20), *m(50, 20), *m(50, 80), *m(30, 60),
                              fill="#FF0000", outline="")
        canvas.create_polygon(*m(50, 20), *m(70, 20), *m(70, 60), *m(50, 80),
                              fill="#FFFF00", outline="")

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
            "seguridad": self.build_seguridad,
            "cuentas": self.build_cuentas,
            "dispositivo": self.build_dispositivo,
            "problemas": self.build_problemas,
            "historial": self.build_historial,
            "configuracion": self.build_configuracion,
        }
        builders.get(frame_name, self.build_seguridad)()

    # ------------------------------------------------------------------- #
    # Info
    # ------------------------------------------------------------------- #
    def build_info(self):
        c = self.colors
        tk.Label(self.content_frame, text="Información", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w")
        datos = [
            f"Nombre del Antivirus: {APP_NAME} Engine",
            f"Versión: {APP_VERSION} (Open Source)",
            "Plataforma: Windows, macOS, Linux",
            f"Firmas cargadas: {len(self.signatures)}",
            f"Hashes en whitelist: {len(self.hash_whitelist)}",
            f"Plugins cargados: {len(self.plugins)}",
            f"psutil disponible: {'Sí' if psutil else 'No'}",
        ]
        for d in datos:
            tk.Label(self.content_frame, text=d, bg=c["bg_main"], fg=c["fg_text"],
                      font=("Arial", 16)).pack(anchor="w", pady=6)

        tk.Button(self.content_frame, text="Acerca de / Aviso legal", command=self.show_about,
                  bg=c["bg_card"], fg="white", font=("Arial", 12), bd=0, padx=10, pady=6,
                  cursor="hand2").pack(anchor="w", pady=(15, 5))
        tk.Button(self.content_frame, text="Atajos de teclado (F1)", command=self.show_shortcuts,
                  bg=c["bg_card"], fg="white", font=("Arial", 12), bd=0, padx=10, pady=6,
                  cursor="hand2").pack(anchor="w")

    def show_about(self):
        top = tk.Toplevel(self.root)
        top.title(f"Acerca de {APP_NAME}")
        top.geometry("480x280")
        top.configure(bg=self.colors["bg_main"])
        texto = (f"{APP_NAME} v{APP_VERSION}\n\n"
                  "Proyecto educativo / de portafolio que simula un motor antivirus.\n\n"
                  "Este software NO sustituye a una solución antivirus comercial.")
        tk.Label(top, text=texto, bg=self.colors["bg_main"], fg=self.colors["fg_text"],
                  font=("Arial", 11), justify="left", wraplength=440).pack(padx=15, pady=15)
        tk.Button(top, text="Cerrar", command=top.destroy).pack(pady=10)

    def show_shortcuts(self):
        top = tk.Toplevel(self.root)
        top.title("Atajos de teclado")
        top.geometry("380x220")
        top.configure(bg=self.colors["bg_main"])
        atajos = [("F5", "Escaneo rápido"), ("F6", "Escaneo completo"),
                  ("Ctrl+P", "Pausar/Reanudar"), ("Ctrl+Q", "Salir"), ("F1", "Ayuda")]
        for tecla, desc in atajos:
            frame = tk.Frame(top, bg=self.colors["bg_card"], pady=4, padx=8)
            frame.pack(fill="x", padx=10, pady=3)
            tk.Label(frame, text=tecla, bg=self.colors["bg_card"], fg="white",
                      font=("Consolas", 11, "bold"), width=8, anchor="w").pack(side="left")
            tk.Label(frame, text=desc, bg=self.colors["bg_card"], fg="white",
                      font=("Arial", 11), anchor="w").pack(side="left")

    # ------------------------------------------------------------------- #
    # Seguridad
    # ------------------------------------------------------------------- #
    def build_seguridad(self):
        c = self.colors
        title_frame = tk.Frame(self.content_frame, bg=c["bg_main"])
        title_frame.pack(fill="x", pady=(0, 10))
        tk.Label(title_frame, text="| Análisis", bg=c["bg_main"], fg=c["fg_title"],
                  font=("Arial", 32)).pack(side="left")
        tk.Label(title_frame, text="🔍", bg=c["bg_main"], fg=c["fg_title"],
                  font=("Arial", 28)).pack(side="left", padx=10)

        btn_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        btn_row.pack(pady=5)
        self.btn_rapido = tk.Button(btn_row, text=self.t("btn_quick"), bg="#5CB85C", fg="white",
                                     font=("Arial", 16), bd=0, width=13, height=2, cursor="hand2",
                                     command=lambda: self.start_scan("Rápido"))
        self.btn_rapido.grid(row=0, column=0, padx=5)
        ToolTip(self.btn_rapido, "Escanea Descargas, Escritorio y Temporales (F5)")
        self.btn_completo = tk.Button(btn_row, text=self.t("btn_full"), bg="black", fg="white",
                                       font=("Arial", 16), bd=0, width=13, height=2, cursor="hand2",
                                       command=lambda: self.start_scan("Completo"))
        self.btn_completo.grid(row=0, column=1, padx=5)
        ToolTip(self.btn_completo, "Escanea toda tu carpeta de usuario (F6)")
        self.btn_personalizado = tk.Button(btn_row, text=self.t("btn_custom"), bg="#337AB7",
                                            fg="white", font=("Arial", 16), bd=0, width=13,
                                            height=2, cursor="hand2",
                                            command=self.start_custom_scan)
        self.btn_personalizado.grid(row=0, column=2, padx=5)

        ctrl_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        ctrl_row.pack(pady=6)
        self.btn_stop = tk.Button(ctrl_row, text="⏹ " + self.t("btn_stop"), bg=c["accent_warn"],
                                   fg="white", font=("Arial", 11), bd=0, padx=10, pady=4,
                                   cursor="hand2", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=3)
        self.btn_pause = tk.Button(ctrl_row, text="⏸ Pausar", bg=c["accent_info"],
                                    fg="black", font=("Arial", 11), bd=0, padx=10, pady=4,
                                    cursor="hand2", command=self.toggle_pause, state="disabled")
        self.btn_pause.pack(side="left", padx=3)
        self.btn_profile = tk.Button(ctrl_row, text="💾 Guardar perfil", bg=c["bg_card"],
                                      fg="white", font=("Arial", 11), bd=0, padx=10, pady=4,
                                      cursor="hand2", command=self.save_current_profile)
        self.btn_profile.pack(side="left", padx=3)

        chk_auto = tk.Checkbutton(self.content_frame, text="Monitoreo de procesos en segundo plano",
                                   variable=self.autoproteccion_activa, bg=c["bg_main"],
                                   fg=c["fg_text"], font=("Arial", 13),
                                   activebackground=c["bg_main"], selectcolor="black",
                                   command=self.toggle_autoproteccion,
                                   state="normal" if psutil else "disabled")
        chk_auto.pack(pady=10, anchor="w")

        info_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        info_row.pack(fill="x", anchor="w")
        tk.Label(info_row, text=f"Firmas: {len(self.signatures)}", bg=c["bg_main"],
                  fg="#CCFFFF", font=("Arial", 10)).pack(side="left", padx=(0, 20))
        ultimo = self.config.get("last_scan")
        ultimo_txt = "Último escaneo: nunca" if not ultimo else (
            f"Último: {ultimo.get('tipo')} — {ultimo.get('amenazas')} amenazas / "
            f"{ultimo.get('escaneados')} archivos")
        self.lbl_ultimo_scan = tk.Label(info_row, text=ultimo_txt, bg=c["bg_main"],
                                         fg="#CCFFFF", font=("Arial", 10))
        self.lbl_ultimo_scan.pack(side="left")

        self.progress = ttk.Progressbar(self.content_frame, mode="indeterminate", length=400)
        self.progress.pack(pady=(10, 0), fill="x")
        self.progress_label = tk.Label(self.content_frame, text="", bg=c["bg_main"],
                                        fg=c["fg_text"], font=("Arial", 10))
        self.progress_label.pack(anchor="w")

        self.log_text = tk.Text(self.content_frame, height=8, width=60, bg=c["log_bg"],
                                 fg=c["log_fg"], font=("Consolas", 10), bd=3, relief="solid")
        self.log_text.pack(pady=8, fill="both", expand=True)
        if self.log_buffer:
            self.log_text.insert("end", "\n".join(self.log_buffer) + "\n")
        else:
            self.log_text.insert("end", "David Secure listo.\n")
        self.log_text.config(state="disabled")

        btns_log = tk.Frame(self.content_frame, bg=c["bg_main"])
        btns_log.pack(anchor="e", pady=(0, 5))
        tk.Button(btns_log, text="Copiar log", command=self.copy_log_to_clipboard,
                  bg=c["bg_card"], fg="white", bd=0, padx=8, pady=3,
                  cursor="hand2").pack(side="left", padx=4)
        tk.Button(btns_log, text="Exportar TXT", command=self.export_report,
                  bg=c["bg_card"], fg="white", bd=0, padx=8, pady=3,
                  cursor="hand2").pack(side="left", padx=4)
        tk.Button(btns_log, text="Exportar CSV", command=self.export_csv,
                  bg=c["bg_card"], fg="white", bd=0, padx=8, pady=3,
                  cursor="hand2").pack(side="left", padx=4)
        tk.Button(btns_log, text="Exportar HTML", command=self.export_html,
                  bg=c["bg_card"], fg="white", bd=0, padx=8, pady=3,
                  cursor="hand2").pack(side="left", padx=4)

        if self.scan_running:
            self._set_scan_buttons_state("disabled")
            self.progress.start(15)

    def start_custom_scan(self):
        carpeta = filedialog.askdirectory(title="Selecciona la carpeta a escanear")
        if carpeta:
            self.start_scan("Personalizado", custom_path=carpeta)

    def copy_log_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.log_buffer))
        messagebox.showinfo(APP_NAME, "Log copiado al portapapeles.")

    def export_report(self):
        ruta = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Texto", "*.txt")],
                                             initialfile="david_secure_reporte.txt")
        if not ruta:
            return
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(f"Reporte {APP_NAME} v{APP_VERSION} - "
                        f"{datetime.now().isoformat(timespec='seconds')}\n")
                f.write("=" * 60 + "\n\n")
                f.write("\n".join(self.log_buffer))
                f.write("\n\nAmenazas en cuarentena:\n")
                for r in self.amenazas_bloqueadas:
                    f.write(f" - {r.get('filename')} | {r.get('threat_name')} | {r.get('date')}\n")
            messagebox.showinfo(APP_NAME, f"Reporte guardado en:\n{ruta}")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"No se pudo guardar: {e}")

    def export_csv(self):
        ruta = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV", "*.csv")],
                                             initialfile="david_secure_historial.csv")
        if not ruta:
            return
        try:
            with open(ruta, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["tipo", "fecha", "escaneados", "amenazas",
                            "duracion_seg", "cancelado"])
                for h in self.config.get("scan_history", []):
                    w.writerow([h.get("tipo"), h.get("fecha"), h.get("escaneados"),
                                h.get("amenazas"), h.get("duracion_seg"), h.get("cancelado")])
            messagebox.showinfo(APP_NAME, f"CSV exportado:\n{ruta}")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Error al exportar CSV: {e}")

    def export_html(self):
        ruta = filedialog.asksaveasfilename(defaultextension=".html",
                                             filetypes=[("HTML", "*.html")],
                                             initialfile="david_secure_reporte.html")
        if not ruta:
            return
        try:
            hist = self.config.get("scan_history", [])
            rows = "".join(
                f"<tr><td>{html_lib.escape(str(h.get('tipo','')))}</td>"
                f"<td>{html_lib.escape(str(h.get('fecha','')))}</td>"
                f"<td>{h.get('escaneados',0)}</td><td>{h.get('amenazas',0)}</td>"
                f"<td>{h.get('duracion_seg',0)}</td></tr>" for h in hist)
            doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Reporte {APP_NAME}</title>
<style>body{{font-family:Arial;background:#f4f4f4;padding:20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:6px;text-align:left}}
th{{background:#3131A1;color:white}}</style></head><body>
<h1>Reporte {APP_NAME} v{APP_VERSION}</h1>
<p>Generado: {datetime.now().isoformat(timespec='seconds')}</p>
<h2>Historial de escaneos</h2>
<table><tr><th>Tipo</th><th>Fecha</th><th>Escaneados</th><th>Amenazas</th><th>Duración (s)</th></tr>
{rows}</table></body></html>"""
            Path(ruta).write_text(doc, encoding="utf-8")
            messagebox.showinfo(APP_NAME, f"HTML exportado:\n{ruta}")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Error al exportar HTML: {e}")

    # ------------------------------------------------------------------- #
    # Cuentas
    # ------------------------------------------------------------------- #
    def build_cuentas(self):
        c = self.colors
        tk.Label(self.content_frame, text="Seguridad de Cuentas", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 28, "bold")).pack(anchor="w", pady=(0, 10))
        tk.Label(self.content_frame, text="(Datos de demostración)",
                  bg=c["bg_main"], fg="#CCFFFF", font=("Arial", 11, "italic")).pack(anchor="w", pady=(0, 15))
        cuentas = [("Correo Electrónico", "Seguro", c["accent_ok"]),
                   ("Redes Sociales", "Contraseña Filtrada", c["accent_warn"]),
                   ("Banca en Línea", "Seguro (2FA)", c["accent_ok"])]
        for cuenta, estado, color in cuentas:
            frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
            frame.pack(fill="x", pady=5)
            tk.Label(frame, text=cuenta, bg=c["bg_card"], fg=c["fg_text"],
                      font=("Arial", 14)).pack(side="left")
            tk.Label(frame, text=estado, bg=c["bg_card"], fg=color,
                      font=("Arial", 14, "bold")).pack(side="right")

    # ------------------------------------------------------------------- #
    # Dispositivo
    # ------------------------------------------------------------------- #
    def build_dispositivo(self):
        c = self.colors
        tk.Label(self.content_frame, text="Seguridad del Dispositivo", bg=c["bg_main"],
                  fg=c["fg_text"], font=("Arial", 28, "bold")).pack(anchor="w", pady=(0, 15))
        info = [("Sistema Operativo", platform.system()), ("Núcleo", platform.release()),
                ("Arquitectura", platform.machine()), ("Cuarentena", str(self.quarantine_dir))]
        if psutil:
            info.append(("Uso de CPU", f"{psutil.cpu_percent(interval=0.2)} %"))
            info.append(("Uso de RAM", f"{psutil.virtual_memory().percent} %"))
            try:
                bat = psutil.sensors_battery()
                if bat:
                    info.append(("Batería", f"{bat.percent:.0f}% "
                                  f"{'(cargando)' if bat.power_plugged else ''}"))
            except Exception:
                pass
            try:
                for part in psutil.disk_partitions(all=False):
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        info.append((f"Disco {part.mountpoint}", f"{usage.percent}% usado"))
                    except Exception:
                        pass
            except Exception:
                pass
        tam_cuarentena = sum(f.stat().st_size for f in self.quarantine_dir.glob("*") if f.is_file())
        info.append(("Tamaño cuarentena", human_readable_size(tam_cuarentena)))
        info.append(("Archivos en cuarentena", str(len(self.amenazas_bloqueadas))))

        for item, valor in info:
            frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
            frame.pack(fill="x", pady=4)
            tk.Label(frame, text=item, bg=c["bg_card"], fg=c["fg_text"],
                      font=("Arial", 13)).pack(side="left")
            tk.Label(frame, text=valor, bg=c["bg_card"], fg=c["accent_ok"],
                      font=("Arial", 12, "bold")).pack(side="right")

        tk.Button(self.content_frame, text="Abrir carpeta de cuarentena",
                  command=lambda: open_folder_in_explorer(str(self.quarantine_dir)),
                  bg=c["bg_card"], fg="white", bd=0, padx=10, pady=6,
                  cursor="hand2").pack(anchor="w", pady=10)

    # ------------------------------------------------------------------- #
    # Problemas / Cuarentena
    # ------------------------------------------------------------------- #
    def build_problemas(self):
        c = self.colors
        tk.Label(self.content_frame, text="Amenazas Bloqueadas", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 28, "bold")).pack(anchor="w", pady=(0, 10))

        top_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        top_row.pack(fill="x", pady=(0, 10))
        tk.Label(top_row, text="Buscar:", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 11)).pack(side="left")
        entry = tk.Entry(top_row, textvariable=self.filter_var, font=("Arial", 11), width=28)
        entry.pack(side="left", padx=8)
        entry.bind("<KeyRelease>", lambda e: self.show_frame("problemas"))
        self._build_quarantine_context_menu(entry)
        tk.Button(top_row, text="Vaciar cuarentena", command=self.vaciar_cuarentena,
                  bg=c["accent_warn"], fg="white", bd=0, padx=10, pady=4,
                  cursor="hand2").pack(side="right")

        filtro = self.filter_var.get().lower().strip()
        registros = [r for r in self.amenazas_bloqueadas
                     if filtro in r.get("filename", "").lower()] if filtro else self.amenazas_bloqueadas

        if not registros:
            tk.Label(self.content_frame, text="No hay amenazas detectadas.",
                      bg=c["bg_main"], fg=c["fg_text"], font=("Arial", 14)).pack(anchor="w")
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

        for registro in registros:
            frame = tk.Frame(scroll_frame, bg=c["accent_warn"], pady=6, padx=10)
            frame.pack(fill="x", pady=3)
            texto = (f"⚠️  {registro.get('filename')} — {registro.get('threat_name')} "
                      f"({registro.get('date','')})")
            tk.Label(frame, text=texto, bg=c["accent_warn"], fg="white",
                      font=("Arial", 11), anchor="w").pack(side="left", fill="x", expand=True)
            tk.Button(frame, text="Restaurar",
                      command=lambda r=registro: self.restore_from_quarantine(r),
                      bg="white", fg="black", bd=0, padx=6,
                      cursor="hand2").pack(side="right", padx=3)
            tk.Button(frame, text="Restaurar como…", command=lambda r=registro: self.restore_as(r),
                      bg="#80D4FF", fg="black", bd=0, padx=6,
                      cursor="hand2").pack(side="right", padx=3)
            tk.Button(frame, text="Ver", command=lambda r=registro: self.preview_quarantine(r),
                      bg="#FFFFE0", fg="black", bd=0, padx=6,
                      cursor="hand2").pack(side="right", padx=3)
            tk.Button(frame, text="Eliminar", command=lambda r=registro: self.delete_permanently(r),
                      bg="black", fg="white", bd=0, padx=6,
                      cursor="hand2").pack(side="right", padx=3)

    def _build_quarantine_context_menu(self, widget):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Restaurar todos", command=self.restore_all)
        menu.add_command(label="Eliminar todos", command=self.vaciar_cuarentena)
        menu.add_separator()
        menu.add_command(label="Exportar selección", command=self.export_quarantine_csv)
        widget.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))

    def restore_all(self):
        if not self.amenazas_bloqueadas:
            return
        if not messagebox.askyesno(APP_NAME, "¿Restaurar TODOS los archivos en cuarentena?"):
            return
        errores = 0
        for r in list(self.amenazas_bloqueadas):
            origen = r.get("quarantine_path")
            destino = r.get("original_path")
            if not origen or not os.path.exists(origen):
                continue
            try:
                os.makedirs(os.path.dirname(destino), exist_ok=True)
                shutil.move(origen, destino)
            except OSError:
                errores += 1
        self.amenazas_bloqueadas = [r for r in self.amenazas_bloqueadas
                                     if os.path.exists(r.get("quarantine_path", ""))]
        save_quarantine_records(self.amenazas_bloqueadas)
        self.show_frame("problemas")
        if errores:
            messagebox.showwarning(APP_NAME, f"Errores al restaurar: {errores}")

    def export_quarantine_csv(self):
        ruta = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV", "*.csv")],
                                             initialfile="cuarentena.csv")
        if not ruta:
            return
        try:
            with open(ruta, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["filename", "threat_name", "date", "original_path", "sha256"])
                for r in self.amenazas_bloqueadas:
                    w.writerow([r.get("filename"), r.get("threat_name"), r.get("date"),
                                r.get("original_path"), r.get("sha256", "")])
            messagebox.showinfo(APP_NAME, f"Exportado:\n{ruta}")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Error: {e}")

    def restore_as(self, registro: dict):
        destino = filedialog.asksaveasfilename(initialfile=registro.get("filename", "restaurado"))
        if not destino:
            return
        origen = registro.get("quarantine_path")
        if not origen or not os.path.exists(origen):
            messagebox.showerror(APP_NAME, "Archivo no encontrado.")
            return
        try:
            shutil.move(origen, destino)
            self.amenazas_bloqueadas = [r for r in self.amenazas_bloqueadas if r is not registro]
            save_quarantine_records(self.amenazas_bloqueadas)
            self.log(f"Restaurado como: {destino}")
            self.show_frame("problemas")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Error: {e}")

    def preview_quarantine(self, registro: dict):
        origen = registro.get("quarantine_path")
        if not origen or not os.path.exists(origen):
            messagebox.showerror(APP_NAME, "Archivo no encontrado.")
            return
        try:
            with open(origen, "rb") as f:
                data = f.read(2048)
            key_bytes = bytes([QUARANTINE_XOR_KEY])
            data = bytes(b ^ key_bytes[i % 1] for i, b in enumerate(data))
            strings = re.findall(rb"[\x20-\x7e]{4,}", data)[:20]
            preview = "\n".join(s.decode("latin1") for s in strings) or "(sin strings legibles)"
        except OSError as e:
            preview = f"Error: {e}"

        top = tk.Toplevel(self.root)
        top.title(f"Previsualizar: {registro.get('filename')}")
        top.geometry("600x400")
        top.configure(bg=self.colors["bg_main"])
        txt = tk.Text(top, bg="black", fg="#B8F397", font=("Consolas", 10))
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.insert("1.0", f"Archivo: {registro.get('filename')}\n"
                          f"Amenaza: {registro.get('threat_name')}\n"
                          f"SHA-256: {registro.get('sha256','')}\n\n"
                          f"--- Strings (primeros 2KB des-ofuscados) ---\n\n{preview}")
        txt.config(state="disabled")

    def restore_from_quarantine(self, registro: dict):
        if not self._verify_password_if_needed():
            return
        origen = registro.get("quarantine_path")
        destino = registro.get("original_path")
        if not origen or not os.path.exists(origen):
            messagebox.showerror(APP_NAME, "El archivo en cuarentena ya no existe.")
            return
        if not messagebox.askyesno(APP_NAME,
                                    f"¿Restaurar '{registro.get('filename')}'?\n"
                                    "Esto puede ser riesgoso."):
            return
        try:
            os.makedirs(os.path.dirname(destino), exist_ok=True)
            shutil.move(origen, destino)
            self.amenazas_bloqueadas = [r for r in self.amenazas_bloqueadas if r is not registro]
            save_quarantine_records(self.amenazas_bloqueadas)
            self.log(f"Archivo restaurado: {registro.get('filename')}")
            self.show_frame("problemas")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"No se pudo restaurar: {e}")

    def _verify_password_if_needed(self) -> bool:
        stored = self.config.get("password_hash")
        if not stored:
            return True
        from tkinter import simpledialog
        pwd = simpledialog.askstring("Contraseña", "Introduce la contraseña:", show="*")
        if not pwd:
            return False
        h = hashlib.sha256(pwd.encode()).hexdigest()
        if h != stored:
            messagebox.showerror(APP_NAME, "Contraseña incorrecta.")
            return False
        return True

    def delete_permanently(self, registro: dict):
        if not self._verify_password_if_needed():
            return
        if not messagebox.askyesno(APP_NAME,
                                    f"¿Eliminar permanentemente '{registro.get('filename')}'?"):
            return
        origen = registro.get("quarantine_path")
        try:
            if origen and os.path.exists(origen):
                try:
                    size = os.path.getsize(origen)
                    with open(origen, "wb") as f:
                        f.write(os.urandom(min(size, 65536)))
                except OSError:
                    pass
                os.remove(origen)
        except OSError as e:
            messagebox.showerror(APP_NAME, f"No se pudo eliminar: {e}")
            return
        self.amenazas_bloqueadas = [r for r in self.amenazas_bloqueadas if r is not registro]
        save_quarantine_records(self.amenazas_bloqueadas)
        self.log(f"Eliminado: {registro.get('filename')}")
        self.show_frame("problemas")

    def vaciar_cuarentena(self):
        if not self.amenazas_bloqueadas:
            return
        if not self._verify_password_if_needed():
            return
        if not messagebox.askyesno(APP_NAME, "¿Eliminar TODOS los archivos en cuarentena?"):
            return
        for registro in list(self.amenazas_bloqueadas):
            origen = registro.get("quarantine_path")
            try:
                if origen and os.path.exists(origen):
                    os.remove(origen)
            except OSError:
                pass
        self.amenazas_bloqueadas = []
        save_quarantine_records(self.amenazas_bloqueadas)
        self.log("Cuarentena vaciada.")
        self.show_frame("problemas")

    # ------------------------------------------------------------------- #
    # Historial
    # ------------------------------------------------------------------- #
    def build_historial(self):
        c = self.colors
        tk.Label(self.content_frame, text="Historial de escaneos", bg=c["bg_main"],
                  fg=c["fg_text"], font=("Arial", 28, "bold")).pack(anchor="w", pady=(0, 10))
        hist = self.config.get("scan_history", [])
        if not hist:
            tk.Label(self.content_frame, text="Sin escaneos registrados aún.",
                      bg=c["bg_main"], fg=c["fg_text"], font=("Arial", 14)).pack(anchor="w")
            return

        total_archivos = sum(h.get("escaneados", 0) for h in hist)
        total_amenazas = sum(h.get("amenazas", 0) for h in hist)
        total_tiempo = sum(h.get("duracion_seg", 0) for h in hist)
        stats = (f"Escaneos totales: {len(hist)}   |   "
                  f"Archivos analizados: {total_archivos}   |   "
                  f"Amenazas: {total_amenazas}   |   "
                  f"Tiempo total: {total_tiempo:.1f}s")
        tk.Label(self.content_frame, text=stats, bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 11, "bold")).pack(anchor="w", fill="x", pady=(0, 10), ipady=6)

        frame = tk.Frame(self.content_frame, bg=c["bg_main"])
        frame.pack(fill="both", expand=True)
        cols = ("Tipo", "Fecha", "Escaneados", "Amenazas", "Duración (s)")
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=15)
        for col in cols:
            tree.heading(col, text=col,
                          command=lambda cc=col: self._sort_tree(tree, cc, False))
            tree.column(col, width=140, anchor="w")
        tree.pack(side="left", fill="both", expand=True)
        sb = tk.Scrollbar(frame, orient="vertical", command=tree.yview)
        sb.pack(side="right", fill="y")
        tree.configure(yscrollcommand=sb.set)
        for h in reversed(hist):
            tree.insert("", "end", values=(h.get("tipo", ""), h.get("fecha", ""),
                                            h.get("escaneados", 0), h.get("amenazas", 0),
                                            h.get("duracion_seg", 0)))
        self._hist_tree = tree

    def _sort_tree(self, tree, col, reverse):
        items = [(tree.set(k, col), k) for k in tree.get_children("")]
        try:
            items.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            items.sort(key=lambda t: t[0], reverse=reverse)
        for index, (_, k) in enumerate(items):
            tree.move(k, "", index)
        tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

    # ------------------------------------------------------------------- #
    # Configuración
    # ------------------------------------------------------------------- #
    def build_configuracion(self):
        c = self.colors
        tk.Label(self.content_frame, text="Configuración", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 28, "bold")).pack(anchor="w", pady=(0, 12))

        # Tema
        tema_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
        tema_frame.pack(fill="x", pady=4)
        tk.Label(tema_frame, text="Tema visual", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 12)).pack(side="left")
        tk.Button(tema_frame, text="Alternar claro/oscuro", command=self.toggle_theme,
                  bg="white", fg="black", bd=0, padx=10, pady=4,
                  cursor="hand2").pack(side="right")

        # Idioma
        lang_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
        lang_frame.pack(fill="x", pady=4)
        tk.Label(lang_frame, text="Idioma", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 12)).pack(side="left")
        self.lang_var = tk.StringVar(value=self.current_lang)
        ttk.Combobox(lang_frame, textvariable=self.lang_var, values=["es", "en"],
                     width=6, state="readonly").pack(side="right")
        tk.Button(lang_frame, text="Aplicar", command=self.apply_language,
                  bg="white", fg="black", bd=0, padx=8,
                  cursor="hand2").pack(side="right", padx=6)

        # Hilos
        thread_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
        thread_frame.pack(fill="x", pady=4)
        tk.Label(thread_frame, text="Hilos de escaneo:", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 12)).pack(side="left")
        self.threads_var = tk.IntVar(value=self.config.get("scan_threads", 4))
        tk.Spinbox(thread_frame, from_=1, to=32, textvariable=self.threads_var, width=6,
                   command=self.save_threads).pack(side="right")

        # Throttle
        throttle_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
        throttle_frame.pack(fill="x", pady=4)
        tk.Label(throttle_frame, text="Throttle por archivo (ms):", bg=c["bg_card"],
                  fg=c["fg_text"], font=("Arial", 12)).pack(side="left")
        self.throttle_var = tk.IntVar(value=self.config.get("scan_throttle_ms", 0))
        tk.Spinbox(throttle_frame, from_=0, to=500, increment=5,
                   textvariable=self.throttle_var, width=6,
                   command=self.save_throttle).pack(side="right")

        # Inspeccionar ZIP
        self.deep_archives_var = tk.BooleanVar(value=self.config.get("deep_archives", True))
        tk.Checkbutton(self.content_frame,
                        text="Inspeccionar contenido de archivos ZIP/Office",
                        variable=self.deep_archives_var, bg=c["bg_main"], fg=c["fg_text"],
                        font=("Arial", 12), activebackground=c["bg_main"],
                        selectcolor="black",
                        command=self.toggle_deep_archives).pack(anchor="w", pady=4)

        # Battery aware
        self.battery_aware_var = tk.BooleanVar(value=self.config.get("battery_aware", True))
        tk.Checkbutton(self.content_frame,
                        text="Pausar escaneo con batería baja (<20%)",
                        variable=self.battery_aware_var, bg=c["bg_main"], fg=c["fg_text"],
                        font=("Arial", 12), activebackground=c["bg_main"],
                        selectcolor="black",
                        command=self.toggle_battery_aware).pack(anchor="w", pady=4)

        # Shutdown after
        self.shutdown_after_var = tk.BooleanVar(value=self.config.get("shutdown_after_scan", False))
        tk.Checkbutton(self.content_frame,
                        text="Apagar el equipo al finalizar escaneo",
                        variable=self.shutdown_after_var, bg=c["bg_main"], fg=c["fg_text"],
                        font=("Arial", 12), activebackground=c["bg_main"],
                        selectcolor="black",
                        command=self.toggle_shutdown_after).pack(anchor="w", pady=4)

        # Exclusiones
        excl_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
        excl_frame.pack(fill="x", pady=4)
        tk.Label(excl_frame, text="Carpetas excluidas:", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 12)).pack(anchor="w")
        self.excl_listbox = tk.Listbox(excl_frame, height=3, font=("Consolas", 9))
        self.excl_listbox.pack(fill="x", pady=4)
        for e in self.config.get("exclusions", []):
            self.excl_listbox.insert("end", e)
        btns = tk.Frame(excl_frame, bg=c["bg_card"])
        btns.pack(anchor="e")
        tk.Button(btns, text="Agregar", command=self.add_exclusion, bg="white", fg="black",
                  bd=0, padx=8, cursor="hand2").pack(side="left", padx=3)
        tk.Button(btns, text="Quitar", command=self.remove_exclusion, bg="white", fg="black",
                  bd=0, padx=8, cursor="hand2").pack(side="left", padx=3)

        # Firmas
        sig_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
        sig_frame.pack(fill="x", pady=4)
        tk.Label(sig_frame, text=f"Firmas: {len(self.signatures)}", bg=c["bg_card"],
                  fg=c["fg_text"], font=("Arial", 12)).pack(side="left")
        tk.Button(sig_frame, text="Importar JSON", command=self.import_signatures,
                  bg="white", fg="black", bd=0, padx=10, pady=4,
                  cursor="hand2").pack(side="right", padx=3)
        tk.Button(sig_frame, text="Actualizar desde URL", command=self.update_signatures_url,
                  bg="white", fg="black", bd=0, padx=10, pady=4,
                  cursor="hand2").pack(side="right", padx=3)

        # Notificaciones
        self.notify_var = tk.BooleanVar(value=self.config.get("notify_on_threat", True))
        tk.Checkbutton(self.content_frame,
                        text="Notificaciones del sistema al detectar amenazas",
                        variable=self.notify_var, bg=c["bg_main"], fg=c["fg_text"],
                        font=("Arial", 12), activebackground=c["bg_main"],
                        selectcolor="black",
                        command=self.toggle_notifications).pack(anchor="w", pady=4)

        # Contraseña
        pwd_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=8, padx=10)
        pwd_frame.pack(fill="x", pady=4)
        tk.Label(pwd_frame, text="Protección por contraseña:", bg=c["bg_card"],
                  fg=c["fg_text"], font=("Arial", 12)).pack(side="left")
        tk.Button(pwd_frame, text="Establecer / Cambiar", command=self.set_password,
                  bg="white", fg="black", bd=0, padx=10, pady=4,
                  cursor="hand2").pack(side="right")

        # Acciones
        acciones_frame = tk.Frame(self.content_frame, bg=c["bg_main"])
        acciones_frame.pack(fill="x", pady=10)
        tk.Button(acciones_frame, text="Vaciar logs", command=self.clear_logs,
                  bg=c["bg_card"], fg="white", bd=0, padx=10, pady=6,
                  cursor="hand2").pack(side="left", padx=4)
        tk.Button(acciones_frame, text="Restablecer config", command=self.reset_config,
                  bg=c["accent_warn"], fg="white", bd=0, padx=10, pady=6,
                  cursor="hand2").pack(side="left", padx=4)
        tk.Button(acciones_frame, text="Restaurar desde backup", command=self.restore_config_backup,
                  bg="#337AB7", fg="white", bd=0, padx=10, pady=6,
                  cursor="hand2").pack(side="left", padx=4)

    # ------------------------------------------------------------------- #
    # Métodos auxiliares de Configuración
    # ------------------------------------------------------------------- #
    def toggle_theme(self):
        self.config["theme"] = "dark" if self.config.get("theme") == "light" else "light"
        save_config(self.config)
        self.build_ui()
        self.show_frame("configuracion")

    def add_exclusion(self):
        carpeta = filedialog.askdirectory(title="Selecciona carpeta a excluir del escaneo")
        if not carpeta:
            return
        exclusiones = self.config.setdefault("exclusions", [])
        if carpeta not in exclusiones:
            exclusiones.append(carpeta)
            save_config(self.config)
            self.excl_listbox.insert("end", carpeta)

    def remove_exclusion(self):
        sel = self.excl_listbox.curselection()
        if not sel:
            return
        valor = self.excl_listbox.get(sel[0])
        exclusiones = self.config.get("exclusions", [])
        if valor in exclusiones:
            exclusiones.remove(valor)
            save_config(self.config)
        self.excl_listbox.delete(sel[0])

    def import_signatures(self):
        ruta = filedialog.askopenfilename(
            title="Selecciona archivo de firmas JSON",
            filetypes=[("JSON", "*.json"), ("Todos", "*.*")]
        )
        if not ruta:
            return
        try:
            self.signatures, agregadas = merge_signatures_from_file(ruta)
            messagebox.showinfo(APP_NAME, f"Se importaron {agregadas} firma(s) nueva(s).")
            self.show_frame("configuracion")
        except (OSError, json.JSONDecodeError, KeyError) as e:
            messagebox.showerror(APP_NAME, f"No se pudo importar el archivo de firmas: {e}")

    def clear_logs(self):
        if messagebox.askyesno(APP_NAME, "¿Vaciar el historial de logs en pantalla?"):
            self.log_buffer.clear()
            self.show_frame("seguridad")

    def reset_config(self):
        if messagebox.askyesno(APP_NAME,
                                "¿Restablecer toda la configuración a los valores por defecto?"):
            self.config = default_config()
            save_config(self.config)
            self.build_ui()
            self.show_frame("configuracion")

    def apply_language(self):
        self.current_lang = self.lang_var.get()
        self.config["language"] = self.current_lang
        save_config(self.config)
        self.build_ui()
        self.show_frame("configuracion")

    def save_threads(self):
        self.config["scan_threads"] = self.threads_var.get()
        save_config(self.config)

    def save_throttle(self):
        self.config["scan_throttle_ms"] = self.throttle_var.get()
        save_config(self.config)

    def toggle_deep_archives(self):
        self.config["deep_archives"] = self.deep_archives_var.get()
        save_config(self.config)

    def toggle_battery_aware(self):
        self.config["battery_aware"] = self.battery_aware_var.get()
        save_config(self.config)

    def toggle_shutdown_after(self):
        self.config["shutdown_after_scan"] = self.shutdown_after_var.get()
        save_config(self.config)

    def toggle_notifications(self):
        self.config["notify_on_threat"] = self.notify_var.get()
        save_config(self.config)

    def set_password(self):
        from tkinter import simpledialog
        pwd = simpledialog.askstring("Contraseña",
                                       "Nueva contraseña (vacío = eliminar):", show="*")
        if pwd is None:
            return
        if pwd == "":
            self.config["password_hash"] = None
            messagebox.showinfo(APP_NAME, "Contraseña eliminada.")
        else:
            self.config["password_hash"] = hashlib.sha256(pwd.encode()).hexdigest()
            messagebox.showinfo(APP_NAME, "Contraseña establecida.")
        save_config(self.config)

    def update_signatures_url(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("Actualizar firmas", "URL del JSON de firmas:")
        if not url:
            return
        added, msg = update_signatures_from_url(url)
        if msg == "OK":
            self.signatures = load_signatures()
            messagebox.showinfo(APP_NAME, f"Se añadieron {added} firmas.")
            self.show_frame("configuracion")
        else:
            messagebox.showerror(APP_NAME, f"Error: {msg}")

    def restore_config_backup(self):
        if not CONFIG_BACKUP_PATH.exists():
            messagebox.showwarning(APP_NAME, "No hay backup disponible.")
            return
        if not messagebox.askyesno(APP_NAME, "¿Restaurar configuración desde backup?"):
            return
        shutil.copy2(CONFIG_BACKUP_PATH, CONFIG_PATH)
        self.config = load_config()
        self.build_ui()
        messagebox.showinfo(APP_NAME, "Configuración restaurada.")

    def save_current_profile(self):
        from tkinter import simpledialog
        nombre = simpledialog.askstring("Guardar perfil", "Nombre del perfil:")
        if not nombre:
            return
        perfiles = load_json(SCAN_PROFILES_PATH, {})
        perfiles[nombre] = {
            "exclusions": self.config.get("exclusions", []),
            "max_hash_size_mb": self.config.get("max_hash_size_mb", 200),
            "scan_threads": self.config.get("scan_threads", 4),
            "deep_archives": self.config.get("deep_archives", True),
        }
        save_json(SCAN_PROFILES_PATH, perfiles)
        messagebox.showinfo(APP_NAME, f"Perfil '{nombre}' guardado.")

    # ------------------------------------------------------------------- #
    # Monitoreo de procesos
    # ------------------------------------------------------------------- #
    def _refresh_status_indicator(self):
        color = self.colors["accent_ok"] if self.monitoring else self.colors["accent_warn"]
        texto = self.t("status_protected") if self.monitoring else self.t("status_unprotected")
        self.status_canvas.itemconfig(self.status_dot, fill=color)
        self.status_label.config(text=texto)

    def toggle_autoproteccion(self):
        self.config["autoproteccion"] = self.autoproteccion_activa.get()
        save_config(self.config)
        with self.state_lock:
            self.monitoring = self.autoproteccion_activa.get()
        self._refresh_status_indicator()
        if self.monitoring:
            messagebox.showinfo(APP_NAME, "Monitoreo de procesos ACTIVADO.")
        else:
            messagebox.showwarning(APP_NAME, "Monitoreo de procesos DESACTIVADO.")

    def log(self, mensaje: str):
        self.logger.info(mensaje)
        self.log_buffer.append(mensaje)
        if len(self.log_buffer) > 5000:
            self.log_buffer = self.log_buffer[-2500:]
        try:
            self.root.after(0, self._update_log, mensaje)
        except RuntimeError:
            pass

    def _update_log(self, mensaje: str):
        if not hasattr(self, "log_text") or not self.log_text.winfo_exists():
            return
        self.log_text.config(state="normal")
        self.log_text.insert("end", mensaje + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")
        if hasattr(self, "status_bar") and self.status_bar.winfo_exists():
            self.status_bar.config(text=mensaje[:120])

    def _set_scan_buttons_state(self, state: str):
        for btn in (getattr(self, "btn_rapido", None),
                    getattr(self, "btn_completo", None),
                    getattr(self, "btn_personalizado", None)):
            if btn is not None and btn.winfo_exists():
                btn.config(state=state)
        if hasattr(self, "btn_stop") and self.btn_stop.winfo_exists():
            self.btn_stop.config(state="normal" if state == "disabled" else "disabled")
        if hasattr(self, "btn_pause") and self.btn_pause.winfo_exists():
            self.btn_pause.config(state="normal" if state == "disabled" else "disabled")

    def stop_scan(self):
        self.scan_cancel_event.set()
        self.scan_pause_event.set()
        self.log("Cancelación solicitada...")

    def toggle_pause(self):
        if self.scan_pause_event.is_set():
            self.scan_pause_event.clear()
            self.log("Escaneo pausado.")
            if hasattr(self, "btn_pause") and self.btn_pause.winfo_exists():
                self.btn_pause.config(text="▶ Reanudar")
        else:
            self.scan_pause_event.set()
            self.log("Escaneo reanudado.")
            if hasattr(self, "btn_pause") and self.btn_pause.winfo_exists():
                self.btn_pause.config(text="⏸ Pausar")

    def start_scan(self, tipo: str, custom_path: Optional[str] = None):
        if self.scan_running:
            messagebox.showwarning(APP_NAME, "Ya hay un escaneo en curso.")
            return
        if self.config.get("battery_aware", True) and psutil:
            try:
                bat = psutil.sensors_battery()
                if bat and not bat.power_plugged and bat.percent < 20:
                    if not messagebox.askyesno(APP_NAME,
                                                f"Batería al {bat.percent:.0f}%. ¿Continuar?"):
                        return
            except Exception:
                pass

        if hasattr(self, "log_text") and self.log_text.winfo_exists():
            self.log_text.config(state="normal")
            self.log_text.delete(1.0, "end")
            self.log_text.config(state="disabled")
        self.log_buffer.clear()

        self.scan_cancel_event.clear()
        self.scan_pause_event.set()
        self.scan_running = True
        self.scan_start_time = time.time()
        self._set_scan_buttons_state("disabled")
        if hasattr(self, "progress"):
            self.progress.start(15)
        threading.Thread(target=self.run_real_scan,
                          args=(tipo, custom_path), daemon=True).start()

    def run_real_scan(self, tipo: str, custom_path: Optional[str] = None):
        try:
            self._run_real_scan_inner(tipo, custom_path)
        except Exception as e:
            self.log(f"[Error inesperado] {e}")
            self.logger.exception("Error inesperado durante el escaneo")
        finally:
            self.scan_running = False
            self.root.after(0, self._on_scan_finished)

    def _on_scan_finished(self):
        self._set_scan_buttons_state("normal")
        if hasattr(self, "progress") and self.progress.winfo_exists():
            self.progress.stop()
        if hasattr(self, "btn_pause") and self.btn_pause.winfo_exists():
            self.btn_pause.config(text="⏸ Pausar")

    def _scan_file(self, filepath: str, max_size_bytes: int) -> dict:
        result = {"path": filepath, "threat": None, "hashes": None,
                  "size": 0, "errors": 0, "skipped": False, "cached": False}
        try:
            size = os.path.getsize(filepath)
            result["size"] = size
        except OSError:
            result["errors"] += 1
            return result

        if self.config.get("incremental", True):
            try:
                mtime = os.path.getmtime(filepath)
                key = file_cache_key(filepath, size, mtime)
                if key in self.scan_cache and self.scan_cache[key].get("clean"):
                    result["cached"] = True
                    return result
            except OSError:
                pass

        hashes = compute_hashes(filepath, max_size_bytes)
        if hashes is None:
            if size > max_size_bytes:
                result["skipped"] = True
            else:
                result["errors"] += 1
            return result
        result["hashes"] = hashes

        if hashes["sha256"].lower() in self.hash_whitelist:
            result["cached"] = True
            return result

        match = match_signature(hashes, self.signatures)
        if match:
            result["threat"] = match
            return result

        nombre = os.path.basename(filepath).lower()

        if nombre.endswith(DOUBLE_EXT_SOSPECHOSAS):
            result["threat"] = {"name": "Doble Extensión",
                                 "severity": "medium", "source": "heuristic"}
            return result

        script_hit = detect_script_patterns(filepath)
        if script_hit:
            result["threat"] = {"name": script_hit, "severity": "high",
                                 "source": "heuristic"}
            return result

        ext = os.path.splitext(nombre)[1]
        if ext and ext not in EXEC_EXTS:
            header = is_executable_content(filepath)
            if header in ("PE/EXE", "ELF") and size > 4096:
                result["threat"] = {"name": f"Ejecutable camuflado ({header})",
                                     "severity": "high", "source": "heuristic"}
                return result

        if size > 8192:
            ent = calculate_entropy(filepath)
            if ent > self.config.get("entropy_threshold", 7.2) and ext in EXEC_EXTS:
                result["threat"] = {"name": f"Posible packer/cifrado (entropía {ent})",
                                     "severity": "low", "source": "heuristic"}
                return result

        if self.config.get("deep_archives", True) and ext in ARCHIVE_EXTS:
            try:
                inside = inspect_archive(filepath)
                if inside:
                    result["threat"] = {"name": f"Ejecutable dentro de archivo: {inside[0]}",
                                         "severity": "medium", "source": "heuristic"}
                    return result
            except Exception:
                pass

        for name, fn in self.plugins:
            try:
                hit = fn(filepath)
                if hit:
                    result["threat"] = {"name": f"Plugin {name}: {hit}",
                                         "severity": "medium", "source": "plugin"}
                    return result
            except Exception:
                pass

        if self.config.get("incremental", True) and not result["threat"]:
            try:
                mtime = os.path.getmtime(filepath)
                key = file_cache_key(filepath, size, mtime)
                self.scan_cache[key] = {"ts": time.time(), "clean": True}
            except OSError:
                pass

        return result

    def _run_real_scan_inner(self, tipo: str, custom_path: Optional[str] = None):
        inicio = time.time()
        self.log(f"Iniciando Análisis {tipo}...")
        time.sleep(0.2)

        user_home = os.path.expanduser("~")
        if custom_path:
            rutas = [custom_path]
        elif tipo == "Rápido":
            rutas = [os.path.join(user_home, "Downloads"), os.path.join(user_home, "Desktop")]
            if platform.system() == "Windows":
                rutas.append(os.environ.get("TEMP", "C:\\Temp"))
            else:
                rutas.append(tempfile.gettempdir())
        else:
            rutas = [user_home]

        exclusions = self.config.get("exclusions", [])
        patterns = self.config.get("exclusion_patterns", [])
        max_size_bytes = self.config.get("max_hash_size_mb", 200) * 1024 * 1024
        num_threads = max(1, self.config.get("scan_threads", 4))
        throttle = self.config.get("scan_throttle_ms", 0) / 1000.0

        archivos_escaneados = 0
        amenazas_encontradas = 0
        omitidos_grandes = 0
        errores = 0
        cacheados = 0
        cancelado = False
        last_update = time.time()

        for ruta in rutas:
            if not os.path.exists(ruta):
                continue
            self.log(f"Escaneando: {ruta}...")
            archivos_pendientes = []
            for root_dir, dirs, files in os.walk(ruta, followlinks=False):
                if self.scan_cancel_event.is_set():
                    cancelado = True
                    break
                dirs[:] = [d for d in dirs
                           if not is_excluded(os.path.join(root_dir, d), exclusions, patterns)]
                for file in files:
                    archivos_pendientes.append(os.path.join(root_dir, file))

            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = {executor.submit(self._scan_file, fp, max_size_bytes): fp
                           for fp in archivos_pendientes}
                for fut in concurrent.futures.as_completed(futures):
                    self.scan_pause_event.wait()
                    if self.scan_cancel_event.is_set():
                        cancelado = True
                        break
                    try:
                        res = fut.result()
                    except Exception:
                        errores += 1
                        continue
                    archivos_escaneados += 1
                    if res["skipped"]:
                        omitidos_grandes += 1
                    elif res["cached"]:
                        cacheados += 1
                    elif res["errors"]:
                        errores += 1
                    elif res["threat"]:
                        threat = res["threat"]
                        self.log(f"Amenaza detectada: {threat['name']} → {res['path']}")
                        registro = self._poner_en_cuarentena(
                            res["path"], threat["name"], res["hashes"] or {})
                        if registro:
                            amenazas_encontradas += 1
                            if self.config.get("notify_on_threat", True):
                                send_notification(APP_NAME,
                                                   f"Amenaza: {threat['name']}")
                    if throttle > 0:
                        time.sleep(throttle)
                    if archivos_escaneados % 100 == 0 and time.time() - last_update > 0.4:
                        elapsed = time.time() - self.scan_start_time
                        speed = archivos_escaneados / elapsed if elapsed > 0 else 0
                        self.root.after(0, self._update_progress_label,
                                         f"{archivos_escaneados} archivos | "
                                         f"{speed:.1f} arch/s | "
                                         f"{amenazas_encontradas} amenazas")
                        last_update = time.time()
                if cancelado:
                    break
            if cancelado:
                break

        save_scan_cache(self.scan_cache)

        duracion = round(time.time() - inicio, 1)
        self.log("----------------------------------------")
        if cancelado:
            self.log(f"Análisis {tipo} CANCELADO.")
        else:
            self.log(f"Análisis {tipo} finalizado.")
        self.log(f"Archivos escaneados: {archivos_escaneados}")
        self.log(f"Amenazas neutralizadas: {amenazas_encontradas}")
        if omitidos_grandes:
            self.log(f"Omitidos por tamaño: {omitidos_grandes}")
        if cacheados:
            self.log(f"Omitidos por caché: {cacheados}")
        if errores:
            self.log(f"Errores: {errores}")
        self.log(f"Duración: {duracion} s")

        if amenazas_encontradas == 0 and not cancelado:
            self.log("El sistema está limpio.")

        resumen = {"tipo": tipo, "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
                   "escaneados": archivos_escaneados, "amenazas": amenazas_encontradas,
                   "duracion_seg": duracion, "cancelado": cancelado,
                   "cacheados": cacheados, "errores": errores}
        self.config["last_scan"] = resumen
        historial = self.config.setdefault("scan_history", [])
        historial.append(resumen)
        self.config["scan_history"] = historial[-50:]
        save_config(self.config)

        if not cancelado:
            self.root.after(0, lambda: messagebox.showinfo(
                APP_NAME, f"Análisis {tipo} completado.\nAmenazas: {amenazas_encontradas}"))
            if self.config.get("shutdown_after_scan", False):
                self.root.after(2000, self._shutdown_system)

    def _update_progress_label(self, texto: str):
        if hasattr(self, "progress_label") and self.progress_label.winfo_exists():
            self.progress_label.config(text=texto)

    def _shutdown_system(self):
        if not messagebox.askyesno(APP_NAME, "¿Apagar el equipo ahora?"):
            return
        try:
            if platform.system() == "Windows":
                os.system("shutdown /s /t 5")
            elif platform.system() == "Darwin":
                os.system("osascript -e 'tell app \"System Events\" to shut down'")
            else:
                os.system("shutdown -h now")
        except Exception as e:
            self.log(f"Error al apagar: {e}")

    def _poner_en_cuarentena(self, filepath: str, nombre_amenaza: str,
                              hashes: dict) -> Optional[dict]:
        original_path = filepath
        result = quarantine_move(filepath, self.quarantine_dir,
                                  password=self.config.get("quarantine_password"))
        if not result:
            return None
        dest, salt = result
        registro = {
            "id": uuid.uuid4().hex,
            "filename": os.path.basename(filepath),
            "original_path": original_path,
            "quarantine_path": dest,
            "threat_name": nombre_amenaza,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "sha256": hashes.get("sha256", ""),
            "salt": salt.hex(),
        }
        with self.state_lock:
            self.amenazas_bloqueadas.append(registro)
            save_quarantine_records(self.amenazas_bloqueadas)
        return registro

    def background_monitor(self):
        """Monitoreo pasivo de procesos y conexiones (solo avisa, no actúa)."""
        procesos_sospechosos = (set(PROCESOS_SOSPECHOSOS_DEFAULT)
                                 - set(self.config.get("process_whitelist", [])))
        ultimo_aviso = 0.0
        known_parents: dict[int, str] = {}

        while not self.monitor_stop_event.is_set():
            if self.monitoring and psutil:
                for proc in psutil.process_iter(["name", "pid", "ppid", "cmdline"]):
                    try:
                        info = proc.info
                        proc_name = (info["name"] or "").lower()
                        if proc_name in procesos_sospechosos and time.time() - ultimo_aviso > 10:
                            self.log(f"Aviso: proceso en lista de vigilancia → {proc_name}")
                            if self.config.get("notify_on_threat", True):
                                send_notification(APP_NAME, f"Aviso: {proc_name}")
                            ultimo_aviso = time.time()

                        cmdline = " ".join(info.get("cmdline") or []).lower()
                        if any(arg in cmdline for arg in ARGUMENTOS_SOSPECHOSOS):
                            if time.time() - ultimo_aviso > 10:
                                self.log(f"Aviso: argumentos inusuales en {proc_name}: "
                                          f"{cmdline[:80]}")
                                ultimo_aviso = time.time()

                        parent_pid = info.get("ppid")
                        if parent_pid and parent_pid in known_parents:
                            parent_name = known_parents[parent_pid]
                            if (parent_name in ("winword.exe", "excel.exe",
                                                 "powerpnt.exe", "outlook.exe")
                                    and proc_name in ("cmd.exe", "powershell.exe",
                                                       "wscript.exe", "cscript.exe")):
                                if time.time() - ultimo_aviso > 10:
                                    self.log(f"Aviso: {parent_name} lanzó {proc_name}")
                                    ultimo_aviso = time.time()

                        known_parents[info["pid"]] = proc_name
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass

                try:
                    for conn in psutil.net_connections(kind="inet"):
                        if conn.status == "ESTABLISHED" and conn.raddr:
                            if conn.raddr.port in (6667, 6668, 31337, 1337, 4444):
                                if time.time() - ultimo_aviso > 10:
                                    self.log(f"Aviso: conexión a puerto inusual → {conn.raddr}")
                                    ultimo_aviso = time.time()
                except (psutil.AccessDenied, AttributeError):
                    pass

            self.monitor_stop_event.wait(self.config.get("monitor_interval_seconds", 5))

    def _schedule_next_scan(self):
        sched = self.config.get("scheduled_scan")
        if not sched:
            return

        def loop():
            while not getattr(self, "_closing", False):
                now = datetime.now()
                try:
                    target = datetime.strptime(sched["hora"], "%H:%M").replace(
                        year=now.year, month=now.month, day=now.day)
                    if target < now:
                        target += timedelta(days=1)
                    wait = (target - now).total_seconds()
                    time.sleep(max(60, wait))
                    if not self.scan_running:
                        self.root.after(0, lambda t=sched.get("tipo", "Rápido"):
                                        self.start_scan(t))
                except (KeyError, ValueError):
                    break
                time.sleep(60)

        threading.Thread(target=loop, daemon=True).start()

    # ------------------------------------------------------------------- #
    # Cierre
    # ------------------------------------------------------------------- #
    def on_close(self):
        if self.scan_running and not messagebox.askyesno(
                APP_NAME, "Hay un escaneo en curso. ¿Cerrar de todas formas?"):
            return
        self._closing = True
        self.scan_cancel_event.set()
        self.monitor_stop_event.set()
        try:
            self.config["window_geometry"] = self.root.geometry()
            save_config(self.config)
            save_scan_cache(self.scan_cache)
        finally:
            release_lock()
            self.root.destroy()


# --------------------------------------------------------------------------- #
# Modo CLI
# --------------------------------------------------------------------------- #
def run_cli_scan(tipo: str, custom_path: Optional[str], logger: logging.Logger,
                  output_json: bool = False, verbose: bool = False) -> int:
    ensure_app_dirs()
    config = load_config()
    signatures = load_signatures()
    hash_whitelist = load_hash_whitelist()
    exclusions = config.get("exclusions", [])
    patterns = config.get("exclusion_patterns", [])
    max_size_bytes = config.get("max_hash_size_mb", 200) * 1024 * 1024
    quarantine_records = load_quarantine_records()

    user_home = os.path.expanduser("~")
    if custom_path:
        rutas = [custom_path]
    elif tipo == "rapido":
        rutas = [os.path.join(user_home, "Downloads"), os.path.join(user_home, "Desktop")]
    else:
        rutas = [user_home]

    if not output_json:
        print(f"{APP_NAME} v{APP_VERSION} — escaneo CLI ({tipo})")
    archivos, amenazas, errores = 0, 0, 0
    inicio = time.time()
    findings = []

    for ruta in rutas:
        if not os.path.exists(ruta):
            continue
        for root_dir, dirs, files in os.walk(ruta, followlinks=False):
            dirs[:] = [d for d in dirs
                       if not is_excluded(os.path.join(root_dir, d), exclusions, patterns)]
            for file in files:
                filepath = os.path.join(root_dir, file)
                archivos += 1
                try:
                    hashes = compute_hashes(filepath, max_size_bytes)
                    if not hashes:
                        continue
                    if hashes["sha256"].lower() in hash_whitelist:
                        continue
                    match = match_signature(hashes, signatures)
                    nombre = match["name"] if match else None
                    if not nombre and file.lower().endswith(DOUBLE_EXT_SOSPECHOSAS):
                        nombre = "Doble Extensión"
                    if not nombre:
                        hit = detect_script_patterns(filepath)
                        if hit:
                            nombre = hit
                    if nombre:
                        dest = quarantine_move(filepath, QUARANTINE_DIR)
                        if dest:
                            dest_path = dest[0] if isinstance(dest, tuple) else dest
                            quarantine_records.append({
                                "id": uuid.uuid4().hex, "filename": file,
                                "original_path": filepath, "quarantine_path": dest_path,
                                "threat_name": nombre,
                                "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                                "sha256": hashes.get("sha256", ""),
                            })
                            amenazas += 1
                            findings.append({"file": file, "threat": nombre, "path": filepath})
                            if verbose:
                                print(f"  [!] {file} -> {nombre} (cuarentena)")
                            logger.info(f"CLI: {file} -> {nombre}")
                except Exception as e:
                    errores += 1
                    if verbose:
                        print(f"  [err] {file}: {e}")
                if archivos % 500 == 0 and not output_json:
                    print(f"  ... {archivos} archivos")

    save_quarantine_records(quarantine_records)
    duracion = round(time.time() - inicio, 1)
    resumen = {"tipo": tipo, "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "escaneados": archivos, "amenazas": amenazas, "duracion_seg": duracion,
                "errores": errores, "cancelado": False}
    config["last_scan"] = resumen
    hist = config.setdefault("scan_history", [])
    hist.append(resumen)
    config["scan_history"] = hist[-50:]
    save_config(config)

    if output_json:
        print(json.dumps({"summary": resumen, "findings": findings},
                          indent=2, ensure_ascii=False))
    else:
        print(f"Listo. Archivos: {archivos} | Amenazas: {amenazas} | "
              f"Errores: {errores} | {duracion}s")
    return 0


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--scan", choices=["rapido", "completo"],
                         help="Escaneo sin GUI")
    parser.add_argument("--path", help="Ruta personalizada")
    parser.add_argument("--json", action="store_true", help="Salida en JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose")
    parser.add_argument("--version", action="version", version=APP_VERSION)
    args = parser.parse_args()

    ensure_app_dirs()

    def _sig_handler(signum, frame):
        print("\nInterrumpido por el usuario.")
        sys.exit(130)
    try:
        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)
    except (ValueError, AttributeError):
        pass

    logger = setup_logger()

    if args.scan:
        sys.exit(run_cli_scan(args.scan, args.path, logger,
                               output_json=args.json, verbose=args.verbose))

    if not acquire_lock():
        print(f"{APP_NAME} ya está en ejecución.")
        sys.exit(1)

    try:
        root = tk.Tk()
        app = DavidSecureApp(root)
        root.mainloop()
    except Exception:
        try:
            crash_path = APP_DIR / f"crash_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            with open(crash_path, "w", encoding="utf-8") as f:
                import traceback
                f.write(traceback.format_exc())
            print(f"Crash log: {crash_path}")
        except OSError:
            pass
        raise
    finally:
        release_lock()


if __name__ == "__main__":
    main()
