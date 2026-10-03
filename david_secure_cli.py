#!/usr/bin/env python3
"""
David Secure CLI — Interfaz de línea de comandos
=================================================
Versión CLI del motor antivirus David Secure v6.1.0.

Novedades:
  • Banner ASCII gigante "DAVID SECURE" en color.
  • El CMD NO se cierra al hacer doble clic (mini-shell final).
  • Cierra escribiendo: salir | exit | quit | q
  • Mini-shell acepta cualquier comando del CLI (scan, url, status, etc.)

Uso:
  david_secure_cli.py <comando> [opciones]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import fnmatch
import hashlib
import json
import math
import os
import platform
import re
import shlex
import shutil
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #
APP_NAME = "David Secure"
APP_VERSION = "6.1.0"

APP_DIR = Path.home() / ".david_secure"
CONFIG_PATH = APP_DIR / "config.json"
CONFIG_BACKUP_PATH = APP_DIR / "config.backup.json"
QUARANTINE_META_PATH = APP_DIR / "quarantine_meta.json"
SIGNATURES_PATH = APP_DIR / "signatures.json"
SIGNATURES_BACKUP_PATH = APP_DIR / "signatures.backup.json"
SCAN_CACHE_PATH = APP_DIR / "scan_cache.json"
URL_BLOCKLIST_PATH = APP_DIR / "url_blocklist.json"
URL_HISTORY_PATH = APP_DIR / "url_history.json"
HASH_WHITELIST_PATH = APP_DIR / "hash_whitelist.json"
PLUGINS_DIR = APP_DIR / "plugins"
LOG_DIR = APP_DIR / "logs"
QUARANTINE_DIR = Path.home() / "DavidSecure_Quarantine"

HASH_BUFFER_SIZE = 65536
QUARANTINE_XOR_KEY = 0x5A

EXEC_EXTS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
             ".js", ".jse", ".wsf", ".ps1", ".hta", ".jar", ".msi"}

DOUBLE_EXT_SOSPECHOSAS = (
    ".pdf.exe", ".docx.exe", ".jpg.exe", ".txt.exe", ".png.exe",
    ".xlsx.exe", ".zip.exe", ".mp3.exe", ".pptx.exe",
)

DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv",
    "$RECYCLE.BIN", "System Volume Information", ".Trash",
}

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

URL_PHISHING_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "account",
    "update", "confirm", "secure", "security", "banking", "password",
    "credential", "wallet", "recovery", "unlock", "suspend", "limited",
    "urgent", "alert", "warning", "billing", "invoice", "payment",
)
URL_BRAND_NAMES = (
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "binance", "coinbase",
    "dropbox", "outlook", "office365", "icloud", "steam", "roblox",
)
URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "shorte.st", "adf.ly", "bc.vc", "t.ly", "v.gd",
)
URL_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".work",
    ".click", ".link", ".loan", ".download", ".review", ".country",
    ".kim", ".men", ".party", ".racing", ".science", ".stream",
    ".gdn", ".bid", ".date", ".faith", ".win", ".accountant",
    ".cricket", ".ninja", ".rocks", ".zip",
}
URL_SUSPICIOUS_DOWNLOAD_EXTS = (
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jar", ".msi",
    ".ps1", ".hta", ".com", ".pif", ".dll", ".apk", ".dmg", ".iso",
)
URL_REDIRECT_PARAMS = ("url=", "redirect=", "next=", "goto=", "redir=",
                       "return=", "continue=", "target=")


# --------------------------------------------------------------------------- #
# Color ANSI
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"


_USE_COLOR = True


def c(text: str, color: str = "", bold: bool = False) -> str:
    if not _USE_COLOR:
        return text
    prefix = ""
    if bold:
        prefix += C.BOLD
    if color:
        prefix += color
    return prefix + text + C.RESET


def eprint(*args, **kwargs):
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


# --------------------------------------------------------------------------- #
# Banner ASCII
# --------------------------------------------------------------------------- #
_ASCII_FONT = {
    "D": ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "V": ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "],
    "I": ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
}


def _render_word(word: str, gap: int = 1) -> list:
    rows = [""] * 6
    for i, ch in enumerate(word.upper()):
        block = _ASCII_FONT.get(ch)
        if not block:
            continue
        for r in range(6):
            if i > 0:
                rows[r] += " " * gap
            rows[r] += block[r]
    return rows


def print_banner(stream=None) -> None:
    if stream is None:
        stream = sys.stderr

    inner = 62
    david = _render_word("DAVID")
    secure = _render_word("SECURE")

    top_border = "╔" + "═" * inner + "╗"
    bot_border = "╚" + "═" * inner + "╝"
    empty_line = "║" + " " * inner + "║"

    def emit(line: str) -> None:
        print(c(line, C.CYAN), file=stream)

    def emit_centered(content: str, raw_len: int, color: str = C.CYAN,
                      bold: bool = False) -> None:
        pad_left = (inner - raw_len) // 2
        pad_right = inner - raw_len - pad_left
        left = " " * pad_left
        right = " " * pad_right
        body = c(content, color, bold=bold)
        emit(c("║", C.CYAN) + left + body + right + c("║", C.CYAN))

    emit(top_border)
    emit(empty_line)

    for row in david:
        emit_centered(row, len(row), color=C.RED, bold=True)

    emit(empty_line)

    for row in secure:
        emit_centered(row, len(row), color=C.YELLOW, bold=True)

    emit(empty_line)

    subtitle = "ANTIVIRUS ENGINE  v" + APP_VERSION
    emit_centered(subtitle, len(subtitle), color=C.CYAN, bold=True)

    emit(empty_line)
    emit(bot_border)


# --------------------------------------------------------------------------- #
# Persistencia
# --------------------------------------------------------------------------- #
def ensure_app_dirs() -> None:
    for d in (APP_DIR, LOG_DIR, QUARANTINE_DIR, PLUGINS_DIR):
        d.mkdir(parents=True, exist_ok=True)


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


def save_json_with_backup(path: Path, backup: Path, data) -> bool:
    if path.exists():
        try:
            shutil.copy2(path, backup)
        except OSError:
            pass
    return save_json(path, data)


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
        "url_check_enabled": True,
        "url_auto_quarantine": True,
        "url_history_limit": 500,
        "silent_notifications": False,
        "auto_scroll_log": True,
        "_version": APP_VERSION,
    }


def load_config() -> dict:
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


def save_config(config: dict) -> None:
    save_json_with_backup(CONFIG_PATH, CONFIG_BACKUP_PATH, config)


# --------------------------------------------------------------------------- #
# Firmas
# --------------------------------------------------------------------------- #
def default_signatures() -> list:
    return [
        {"hash": "44d88612fea8a8f36de82e1278abb02f", "algo": "md5",
         "name": "EICAR Test File", "severity": "test"},
        {"hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0",
         "algo": "sha256", "name": "EICAR Test File", "severity": "test"},
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


def merge_signatures_from_file(path: str) -> tuple:
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


def update_signatures_from_url(url: str, timeout: int = 15) -> tuple:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        return 0, "Error: " + str(e)
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


# --------------------------------------------------------------------------- #
# Cuarentena / blocklist / whitelist
# --------------------------------------------------------------------------- #
def load_quarantine_records() -> list:
    return load_json(QUARANTINE_META_PATH, [])


def save_quarantine_records(records: list) -> None:
    save_json(QUARANTINE_META_PATH, records)


def load_url_blocklist() -> list:
    return load_json(URL_BLOCKLIST_PATH, [])


def save_url_blocklist(items: list) -> None:
    save_json(URL_BLOCKLIST_PATH, items)


def load_url_history() -> list:
    return load_json(URL_HISTORY_PATH, [])


def save_url_history(items: list) -> None:
    save_json(URL_HISTORY_PATH, items)


def load_hash_whitelist() -> set:
    return set(h.lower() for h in load_json(HASH_WHITELIST_PATH, []))


def save_hash_whitelist(hashes: set) -> None:
    save_json(HASH_WHITELIST_PATH, sorted(hashes))


# --------------------------------------------------------------------------- #
# Core engine
# --------------------------------------------------------------------------- #
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
        for cnt in counts.values():
            p = cnt / length
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


def is_excluded(dirpath: str, exclusions: list, patterns: Optional[list] = None) -> bool:
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


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def human_readable_size(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return "{:.1f} {}".format(num_bytes, unit)
        num_bytes /= 1024.0
    return "{:.1f} PB".format(num_bytes)


# --------------------------------------------------------------------------- #
# Analizador de URL
# --------------------------------------------------------------------------- #
def analyze_url(raw_url: str) -> dict:
    result = {
        "url": raw_url.strip(),
        "score": 0,
        "is_threat": False,
        "category": "clean",
        "hostname": "",
        "reasons": [],
    }
    if not raw_url or not raw_url.strip():
        result["reasons"].append("URL vacía")
        result["category"] = "invalid"
        return result

    url = raw_url.strip()
    url_lower = url.lower()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url_lower):
        url_work = "http://" + url_lower
    else:
        url_work = url_lower

    try:
        parsed = urllib.parse.urlparse(url_work)
    except ValueError:
        result["reasons"].append("URL malformada")
        result["score"] = 60
        result["is_threat"] = True
        result["category"] = "malicious"
        return result

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    netloc = parsed.netloc or ""
    result["hostname"] = hostname

    reasons = []
    score = 0

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 35
        reasons.append("Host es una dirección IP cruda")

    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        score += 12
        reasons.append("Puerto inusual: {}".format(parsed.port))

    if any(s in hostname for s in URL_SHORTENERS):
        score += 25
        reasons.append("Acortador de URL (destino oculto)")

    for tld in URL_SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 18
            reasons.append("TLD frecuentemente abusado: {}".format(tld))
            break

    if "@" in netloc:
        score += 35
        reasons.append("Credenciales embebidas en la URL (@)")

    if hostname.count(".") > 3:
        score += 15
        reasons.append("Demasiados subdominios ({})".format(hostname.count(".")))

    if "xn--" in hostname:
        score += 30
        reasons.append("Posible ataque homograph (punycode xn--)")

    for kw in URL_PHISHING_KEYWORDS:
        if kw in url_lower:
            score += 8
            reasons.append("Palabra clave sensible: '{}'".format(kw))
            break

    for brand in URL_BRAND_NAMES:
        if brand in url_lower and not hostname.endswith(brand + ".com"):
            score += 20
            reasons.append("Posible suplantación de marca: {}".format(brand))
            break

    for ext in URL_SUSPICIOUS_DOWNLOAD_EXTS:
        if path.lower().endswith(ext) or (ext + "?") in url_lower:
            score += 30
            reasons.append("Descarga de archivo ejecutable: {}".format(ext))
            break

    if re.search(r"\.(pdf|docx?|jpg|png|txt|xlsx?|zip)\.(exe|scr|bat|cmd|vbs|js|ps1)",
                 url_lower):
        score += 30
        reasons.append("Doble extensión sospechosa en URL")

    if len(url) > 150:
        score += 10
        reasons.append("URL muy larga ({} caracteres)".format(len(url)))

    if query.count("&") > 5:
        score += 10
        reasons.append("Muchos parámetros de consulta")

    if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}", url_lower):
        score += 15
        reasons.append("Codificación hexadecimal repetida")

    if url_lower.startswith("data:"):
        score += 45
        reasons.append("Data URI (posible ofuscación)")

    if url_lower.startswith("http://"):
        score += 5
        reasons.append("No utiliza HTTPS")

    if any(p in query for p in URL_REDIRECT_PARAMS):
        score += 15
        reasons.append("Contiene parámetro de redirección")

    if len(path) > 20:
        ent = shannon_entropy(path)
        if ent > 4.0:
            score += 10
            reasons.append("Alta entropía en la ruta ({})".format(ent))

    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", url):
        score += 12
        reasons.append("Posible cadena Base64 embebida")

    if hostname.count("-") >= 3:
        score += 10
        reasons.append("Dominio con muchos guiones")

    score = min(score, 100)
    result["score"] = score
    result["reasons"] = reasons or ["Sin indicadores sospechosos"]
    if score >= 70:
        result["category"] = "malicious"
        result["is_threat"] = True
    elif score >= 40:
        result["category"] = "suspicious"
        result["is_threat"] = False
    else:
        result["category"] = "clean"
        result["is_threat"] = False
    return result


# --------------------------------------------------------------------------- #
# Cuarentena
# --------------------------------------------------------------------------- #
def quarantine_move(filepath: str, quarantine_dir: Path,
                    password: Optional[str] = None) -> Optional[tuple]:
    try:
        filename = os.path.basename(filepath)
        dest = quarantine_dir / (filename + ".locked")
        if dest.exists():
            stem, _ = os.path.splitext(filename)
            dest = quarantine_dir / (stem + "_" + uuid.uuid4().hex[:8] + ".locked")

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


def quarantine_restore(locked_path: str, dest_path: str,
                       password: Optional[str] = None) -> bool:
    try:
        with open(locked_path, "rb") as f:
            data = f.read()
        if len(data) < 16:
            return False
        salt, encrypted = data[:16], data[16:]
        if password:
            key_bytes = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 50000)
        else:
            key_bytes = bytes([QUARANTINE_XOR_KEY])
        key_len = len(key_bytes)
        decrypted = bytes(b ^ key_bytes[i % key_len] for i, b in enumerate(encrypted))
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(decrypted)
        os.remove(locked_path)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Utilidades de impresión
# --------------------------------------------------------------------------- #
def print_header(title: str):
    print()
    print(c("═══ " + title + " ═══", C.CYAN, bold=True))


def print_kv(key: str, value: str, color: str = ""):
    key_str = c("{:<28}".format(key), C.DIM)
    print("  " + key_str + " " + c(value, color))


def print_ok(msg: str):
    print("  " + c("✓", C.GREEN, bold=True) + " " + msg)


def print_warn(msg: str):
    print("  " + c("⚠", C.YELLOW, bold=True) + " " + msg)


def print_err(msg: str):
    eprint("  " + c("✗", C.RED, bold=True) + " " + msg)


def print_info(msg: str):
    print("  " + c("ℹ", C.BLUE, bold=True) + " " + msg)


def progress_line(done: int, total: int, threats: int, speed: float, width: int = 30):
    pct = (done / total * 100) if total else 0
    filled = int(width * pct / 100)
    bar = "█" * filled + "░" * (width - filled)
    threats_str = c(str(threats), C.RED if threats else C.GREEN, bold=True)
    line = "\r  [{}] {}/{} ({:5.1f}%) {:6.1f}/s amenazas:{}".format(
        bar, done, total, pct, speed, threats_str)
    sys.stdout.write(line)
    sys.stdout.flush()


# --------------------------------------------------------------------------- #
# Comando: scan
# --------------------------------------------------------------------------- #
_SCAN_CANCEL = False


def _handle_signal(signum, frame):
    global _SCAN_CANCEL
    if _SCAN_CANCEL:
        print()
        sys.exit(130)
    _SCAN_CANCEL = True
    eprint(c("\n[!] Cancelación solicitada. Pulsa Ctrl+C de nuevo para forzar salida.",
             C.YELLOW))


def _scan_single(filepath: str, max_size_bytes: int, signatures: list,
                 hash_whitelist: set, config: dict) -> dict:
    result = {"path": filepath, "threat": None, "hashes": None,
              "size": 0, "errors": 0, "skipped": False}
    try:
        size = os.path.getsize(filepath)
        result["size"] = size
    except OSError:
        result["errors"] += 1
        return result

    hashes = compute_hashes(filepath, max_size_bytes)
    if hashes is None:
        if size > max_size_bytes:
            result["skipped"] = True
        else:
            result["errors"] += 1
        return result
    result["hashes"] = hashes

    if hashes["sha256"].lower() in hash_whitelist:
        return result

    match = match_signature(hashes, signatures)
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
            result["threat"] = {"name": "Ejecutable camuflado ({})".format(header),
                                "severity": "high", "source": "heuristic"}
            return result

    if size > 8192:
        ent = calculate_entropy(filepath)
        if ent > config.get("entropy_threshold", 7.2) and ext in EXEC_EXTS:
            result["threat"] = {"name": "Posible packer/cifrado (entropía {})".format(ent),
                                "severity": "low", "source": "heuristic"}
            return result

    if config.get("deep_archives", True) and ext in ARCHIVE_EXTS:
        try:
            inside = inspect_archive(filepath)
            if inside:
                result["threat"] = {
                    "name": "Ejecutable dentro de archivo: {}".format(inside[0]),
                    "severity": "medium", "source": "heuristic"}
                return result
        except Exception:
            pass

    return result


def cmd_scan(args) -> int:
    global _SCAN_CANCEL
    _SCAN_CANCEL = False

    try:
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except (ValueError, AttributeError):
        pass

    ensure_app_dirs()
    config = load_config()
    signatures = load_signatures()
    hash_whitelist = load_hash_whitelist()
    exclusions = config.get("exclusions", [])
    patterns = config.get("exclusion_patterns", [])
    max_size_bytes = config.get("max_hash_size_mb", 200) * 1024 * 1024
    quarantine_password = config.get("quarantine_password")

    user_home = os.path.expanduser("~")
    if getattr(args, "path", None):
        rutas = [args.path]
        tipo = "custom"
    elif args.tipo == "rapido":
        rutas = [os.path.join(user_home, "Downloads"),
                 os.path.join(user_home, "Desktop")]
        if platform.system() == "Windows":
            rutas.append(os.environ.get("TEMP", "C:\\Temp"))
        else:
            rutas.append(tempfile.gettempdir())
        tipo = "rapido"
    else:
        rutas = [user_home]
        tipo = "completo"

    rutas = [r for r in rutas if os.path.exists(r)]
    if not rutas:
        print_err("No hay rutas válidas para escanear.")
        return 1

    if not args.json and not args.quiet:
        print_header("Escaneo " + tipo)
        for r in rutas:
            print("  • " + c(r, C.DIM))
        print()

    archivos_pendientes = []
    for ruta in rutas:
        for root_dir, dirs, files in os.walk(ruta, followlinks=False):
            if _SCAN_CANCEL:
                break
            dirs[:] = [d for d in dirs
                       if not is_excluded(os.path.join(root_dir, d), exclusions, patterns)]
            for fname in files:
                archivos_pendientes.append(os.path.join(root_dir, fname))
        if _SCAN_CANCEL:
            break

    total = len(archivos_pendientes)
    if total == 0:
        print_warn("No se encontraron archivos para escanear.")
        return 0

    num_threads = max(1, int(config.get("scan_threads", 4)))
    throttle = config.get("scan_throttle_ms", 0) / 1000.0
    no_quarantine = getattr(args, "no_quarantine", False)

    scans, threats, errors, skipped = 0, 0, 0, 0
    findings = []
    inicio = time.time()
    last_render = 0.0
    quarantine_records = load_quarantine_records()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(_scan_single, fp, max_size_bytes, signatures,
                                   hash_whitelist, config): fp
                   for fp in archivos_pendientes}
        for fut in concurrent.futures.as_completed(futures):
            if _SCAN_CANCEL:
                break
            scans += 1
            try:
                res = fut.result()
            except Exception:
                errors += 1
                continue

            if res["skipped"]:
                skipped += 1
            elif res["errors"]:
                errors += 1
            elif res["threat"]:
                threats += 1
                threat = res["threat"]
                finding = {
                    "path": res["path"],
                    "threat": threat["name"],
                    "severity": threat["severity"],
                    "source": threat["source"],
                    "sha256": (res["hashes"] or {}).get("sha256", ""),
                    "quarantined": False,
                }
                if not no_quarantine:
                    qres = quarantine_move(res["path"], QUARANTINE_DIR,
                                           password=quarantine_password)
                    if qres:
                        dest, salt = qres
                        finding["quarantined"] = True
                        quarantine_records.append({
                            "id": uuid.uuid4().hex,
                            "filename": os.path.basename(res["path"]),
                            "original_path": res["path"],
                            "quarantine_path": dest,
                            "threat_name": threat["name"],
                            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "sha256": finding["sha256"],
                            "salt": salt.hex(),
                            "type": "file",
                        })
                findings.append(finding)
                if not args.json and not args.quiet:
                    sys.stdout.write("\r" + " " * 100 + "\r")
                    color = C.RED if threat["severity"] in ("high", "test") else C.YELLOW
                    bname = c(os.path.basename(res["path"]), C.BOLD)
                    tname = c(threat["name"], color)
                    icon = c("⚠", color, bold=True)
                    qtxt = " → cuarentena" if finding["quarantined"] else ""
                    print("  {} {} → {} [{}]{}".format(
                        icon, bname, tname, threat["severity"], qtxt))

            if throttle > 0:
                time.sleep(throttle)

            now = time.time()
            if not args.json and not args.quiet and now - last_render > 0.1:
                speed = scans / (now - inicio) if now > inicio else 0
                progress_line(scans, total, threats, speed)
                last_render = now

    if not args.json and not args.quiet:
        sys.stdout.write("\r" + " " * 100 + "\r")

    save_quarantine_records(quarantine_records)
    duracion = round(time.time() - inicio, 1)

    resumen = {
        "tipo": tipo,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "escaneados": scans,
        "amenazas": threats,
        "duracion_seg": duracion,
        "errores": errors,
        "omitidos_tamano": skipped,
        "cancelado": _SCAN_CANCEL,
    }
    config["last_scan"] = resumen
    hist = config.setdefault("scan_history", [])
    hist.append(resumen)
    config["scan_history"] = hist[-50:]
    save_config(config)

    if args.json:
        print(json.dumps({"summary": resumen, "findings": findings},
                         indent=2, ensure_ascii=False))
    elif not args.quiet:
        print_header("Resumen")
        print_kv("Archivos escaneados:", str(scans))
        threats_color = C.RED if threats else C.GREEN
        print_kv("Amenazas neutralizadas:", str(threats), threats_color)
        if skipped:
            print_kv("Omitidos por tamaño:", str(skipped), C.DIM)
        if errors:
            print_kv("Errores:", str(errors), C.YELLOW)
        print_kv("Duración:", "{}s".format(duracion))
        estado = "CANCELADO" if _SCAN_CANCEL else "COMPLETADO"
        print_kv("Estado:", estado, C.YELLOW if _SCAN_CANCEL else C.GREEN)
        if threats == 0 and not _SCAN_CANCEL:
            print()
            print("  " + c("✓ El sistema está limpio.", C.GREEN, bold=True))
        print()

    if _SCAN_CANCEL:
        return 130
    if getattr(args, "fail_on_threat", False) and threats > 0:
        return 2
    return 0


# --------------------------------------------------------------------------- #
# Comando: url
# --------------------------------------------------------------------------- #
def cmd_url(args) -> int:
    ensure_app_dirs()
    config = load_config()
    url = args.url
    result = analyze_url(url)
    blocklist = load_url_blocklist()
    hostname = result.get("hostname", "")
    already_blocked = url in blocklist or (hostname and hostname in blocklist)
    if already_blocked:
        result["is_threat"] = True
        result["category"] = "blocked"
        result["score"] = max(result["score"], 80)
        if "URL ya en lista de bloqueo" not in result["reasons"]:
            result["reasons"].insert(0, "URL ya en lista de bloqueo")

    history = load_url_history()
    history.append({
        "ts": time.time(),
        "url": result["url"],
        "hostname": result.get("hostname", ""),
        "score": result["score"],
        "category": result["category"],
    })
    limit = max(50, int(config.get("url_history_limit", 500)))
    if len(history) > limit:
        history = history[-limit:]
    save_url_history(history)

    quarantined = False
    if result["is_threat"] and not getattr(args, "no_block", False):
        if url not in blocklist:
            blocklist.append(url)
            save_url_blocklist(blocklist)
        records = load_quarantine_records()
        records.append({
            "id": uuid.uuid4().hex,
            "filename": url,
            "original_path": url,
            "quarantine_path": None,
            "threat_name": "URL." + result["category"].upper(),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "sha256": hashlib.sha256(url.encode()).hexdigest(),
            "type": "url",
            "score": result["score"],
            "reasons": result["reasons"][:8],
        })
        save_quarantine_records(records)
        quarantined = True

    if getattr(args, "json", False):
        result["quarantined"] = quarantined
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        cat = result["category"]
        if cat in ("malicious", "blocked"):
            color, icon, label = C.RED, "⛔", "PELIGROSA"
        elif cat == "suspicious":
            color, icon, label = C.YELLOW, "⚠️ ", "SOSPECHOSA"
        elif cat == "invalid":
            color, icon, label = C.YELLOW, "❓", "URL INVÁLIDA"
        else:
            color, icon, label = C.GREEN, "✅", "SEGURA"

        print()
        head = c(icon, color, bold=True) + " " + c(label, color, bold=True)
        print("  " + head + "  (score: {}/100)".format(result["score"]))
        print()
        print_kv("URL:", result["url"])
        print_kv("Host:", hostname or "(desconocido)")
        print_kv("Categoría:", cat, color)
        if quarantined:
            print_kv("Acción:", "Añadida a blocklist + cuarentena", C.RED)
        elif result["is_threat"] and getattr(args, "no_block", False):
            print_kv("Acción:", "Detectada pero NO bloqueada (--no-block)", C.YELLOW)
        print()
        print("  " + c("Motivos:", C.DIM))
        for r in result["reasons"]:
            print("    • " + r)
        print()

    if result["is_threat"]:
        return 2
    return 0


# --------------------------------------------------------------------------- #
# Comando: quarantine
# --------------------------------------------------------------------------- #
def _resolve_record(records: list, ident: str) -> Optional[dict]:
    for r in records:
        if r.get("id", "").startswith(ident):
            return r
    for r in records:
        if r.get("filename") == ident:
            return r
    return None


def cmd_quarantine(args) -> int:
    ensure_app_dirs()
    records = load_quarantine_records()
    action = args.action

    if action == "list":
        if getattr(args, "json", False):
            print(json.dumps(records, indent=2, ensure_ascii=False))
            return 0
        if not records:
            print_info("La cuarentena está vacía.")
            return 0
        print_header("Cuarentena ({} elementos)".format(len(records)))
        for r in records:
            is_url = r.get("type") == "url"
            icon = "🌐" if is_url else "📄"
            name = r.get("filename", "?")
            threat = r.get("threat_name", "?")
            date = r.get("date", "?")
            color = C.MAGENTA if is_url else C.RED
            short_id = c(r.get("id", "")[:12], C.DIM)
            print("  " + c(icon, color) + " " + c(name, C.BOLD))
            print("     id: {}  amenaza: {}  fecha: {}".format(
                short_id, c(threat, color), date))
            if is_url:
                print("     score: {}".format(r.get("score", "?")))
            else:
                print("     origen: {}".format(r.get("original_path", "")))
        print()
        return 0

    if action == "restore":
        rec = _resolve_record(records, args.id)
        if not rec:
            print_err("No se encontró registro con id/nombre: " + args.id)
            return 1
        if rec.get("type") == "url":
            print_err("Esta entrada es una URL; usa 'quarantine delete' para quitarla.")
            return 1
        origen = rec.get("quarantine_path")
        destino = getattr(args, "to", None) or rec.get("original_path")
        if not origen or not os.path.exists(origen):
            print_err("El archivo en cuarentena ya no existe.")
            return 1
        if os.path.exists(destino) and not getattr(args, "force", False):
            print_err("El destino ya existe: {}. Usa --force para sobrescribir.".format(destino))
            return 1
        pwd = None
        if load_config().get("quarantine_password"):
            import getpass
            pwd = getpass.getpass("Contraseña de cuarentena: ")
        ok = quarantine_restore(origen, destino, password=pwd)
        if not ok:
            print_err("No se pudo restaurar el archivo.")
            return 1
        records = [r for r in records if r is not rec]
        save_quarantine_records(records)
        print_ok("Restaurado en: " + destino)
        return 0

    if action == "delete":
        rec = _resolve_record(records, args.id)
        if not rec:
            print_err("No se encontró registro con id/nombre: " + args.id)
            return 1
        if rec.get("type") != "url":
            origen = rec.get("quarantine_path")
            try:
                if origen and os.path.exists(origen):
                    os.remove(origen)
            except OSError as e:
                print_err("No se pudo eliminar: " + str(e))
                return 1
        else:
            blocklist = load_url_blocklist()
            url = rec.get("filename")
            if url in blocklist:
                blocklist.remove(url)
                save_url_blocklist(blocklist)
        records = [r for r in records if r is not rec]
        save_quarantine_records(records)
        print_ok("Eliminado: " + str(rec.get("filename")))
        return 0

    if action == "empty":
        if not records:
            print_info("La cuarentena ya está vacía.")
            return 0
        if not getattr(args, "yes", False):
            resp = input("¿Eliminar {} elementos de cuarentena? [y/N] ".format(
                len(records))).strip().lower()
            if resp not in ("y", "yes", "s", "si", "sí"):
                print_info("Cancelado.")
                return 0
        removed = 0
        for r in records:
            if r.get("type") == "url":
                continue
            origen = r.get("quarantine_path")
            try:
                if origen and os.path.exists(origen):
                    os.remove(origen)
                    removed += 1
            except OSError:
                pass
        save_quarantine_records([])
        save_url_blocklist([])
        print_ok("Cuarentena vaciada ({} archivos eliminados, {} entradas borradas).".format(
            removed, len(records)))
        return 0

    if action == "export":
        dest = getattr(args, "path", None) or "cuarentena_{}.csv".format(
            datetime.now().strftime("%Y%m%d_%H%M%S"))
        try:
            with open(dest, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["type", "filename", "threat_name", "date",
                            "original_path", "sha256"])
                for r in records:
                    w.writerow([r.get("type", "file"), r.get("filename", ""),
                                r.get("threat_name", ""), r.get("date", ""),
                                r.get("original_path", ""), r.get("sha256", "")])
            print_ok("Exportado: " + dest)
            return 0
        except OSError as e:
            print_err("Error al exportar: " + str(e))
            return 1

    if action == "show":
        rec = _resolve_record(records, args.id)
        if not rec:
            print_err("No se encontró: " + args.id)
            return 1
        if getattr(args, "json", False):
            print(json.dumps(rec, indent=2, ensure_ascii=False))
        else:
            print_header("Registro " + rec.get("id", "")[:12])
            for k, v in rec.items():
                if isinstance(v, list):
                    print_kv(k + ":", "")
                    for item in v:
                        print("     • " + str(item))
                else:
                    print_kv(k + ":", str(v))
        return 0

    return 1


# --------------------------------------------------------------------------- #
# Comando: blocklist
# --------------------------------------------------------------------------- #
def cmd_blocklist(args) -> int:
    ensure_app_dirs()
    blocklist = load_url_blocklist()
    action = args.action

    if action == "list":
        if getattr(args, "json", False):
            print(json.dumps(blocklist, indent=2, ensure_ascii=False))
            return 0
        if not blocklist:
            print_info("La lista de bloqueo está vacía.")
            return 0
        print_header("URLs bloqueadas ({})".format(len(blocklist)))
        for u in blocklist:
            print("  " + c("•", C.MAGENTA) + " " + u)
        print()
        return 0

    if action == "add":
        if args.url in blocklist:
            print_info("La URL ya está en la lista: " + args.url)
            return 0
        blocklist.append(args.url)
        save_url_blocklist(blocklist)
        print_ok("Añadida: " + args.url)
        return 0

    if action == "remove":
        if args.url not in blocklist:
            print_err("No se encontró en la lista: " + args.url)
            return 1
        blocklist.remove(args.url)
        save_url_blocklist(blocklist)
        print_ok("Eliminada: " + args.url)
        return 0

    if action == "clear":
        if not blocklist:
            print_info("Ya está vacía.")
            return 0
        if not getattr(args, "yes", False):
            resp = input("¿Vaciar {} URLs? [y/N] ".format(len(blocklist))).strip().lower()
            if resp not in ("y", "yes", "s", "si", "sí"):
                print_info("Cancelado.")
                return 0
        save_url_blocklist([])
        print_ok("Blocklist vaciada.")
        return 0

    return 1


# --------------------------------------------------------------------------- #
# Comando: sigs
# --------------------------------------------------------------------------- #
def cmd_sigs(args) -> int:
    ensure_app_dirs()
    action = args.action

    if action == "list":
        sigs = load_signatures()
        if getattr(args, "json", False):
            print(json.dumps(sigs, indent=2, ensure_ascii=False))
            return 0
        print_header("Firmas ({})".format(len(sigs)))
        for s in sigs:
            h = s.get("hash", "")[:16] + "…"
            algo = str(s.get("algo", "?"))
            name = str(s.get("name", "?"))
            sev = str(s.get("severity", "?"))
            algo_col = c("{:<8}".format(algo), C.DIM)
            hash_col = c(h, C.CYAN)
            name_col = c(name, C.BOLD)
            print("  " + algo_col + " " + hash_col + "  " + name_col + " [" + sev + "]")
        print()
        return 0

    if action == "import":
        try:
            _, added = merge_signatures_from_file(args.path)
            print_ok("Se importaron {} firma(s) nuevas.".format(added))
            return 0
        except (OSError, json.JSONDecodeError, KeyError) as e:
            print_err("No se pudo importar: " + str(e))
            return 1

    if action == "update":
        added, msg = update_signatures_from_url(args.url)
        if msg == "OK":
            print_ok("Se añadieron {} firmas desde {}".format(added, args.url))
            return 0
        print_err("Error al actualizar: " + msg)
        return 1

    if action == "add":
        sigs = load_signatures()
        h = args.hash.lower()
        algo = args.algo
        for s in sigs:
            if s.get("hash", "").lower() == h and s.get("algo") == algo:
                print_info("La firma ya existe.")
                return 0
        sigs.append({
            "hash": h, "algo": algo,
            "name": args.name, "severity": args.severity,
        })
        save_json_with_backup(SIGNATURES_PATH, SIGNATURES_BACKUP_PATH, sigs)
        print_ok("Añadida firma {}:{}…".format(algo, h[:16]))
        return 0

    return 1


# --------------------------------------------------------------------------- #
# Comando: config
# --------------------------------------------------------------------------- #
def cmd_config(args) -> int:
    ensure_app_dirs()
    action = args.action

    if action == "show":
        cfg = load_config()
        if getattr(args, "json", False):
            print(json.dumps(cfg, indent=2, ensure_ascii=False))
            return 0
        print_header("Configuración actual")
        for k in sorted(cfg.keys()):
            if k.startswith("_"):
                continue
            v = cfg[k]
            if isinstance(v, (list, dict)):
                v = "{}[{}]".format(type(v).__name__, len(v))
            print_kv(k + ":", str(v))
        print()
        return 0

    if action == "get":
        cfg = load_config()
        if args.key not in cfg:
            print_err("Clave desconocida: " + args.key)
            return 1
        v = cfg[args.key]
        if getattr(args, "json", False):
            print(json.dumps({args.key: v}, indent=2, ensure_ascii=False))
        else:
            if isinstance(v, (dict, list)):
                print(json.dumps(v, indent=2, ensure_ascii=False))
            else:
                print(v)
        return 0

    if action == "set":
        cfg = load_config()
        if args.key not in cfg:
            print_err("Clave desconocida: " + args.key)
            return 1
        raw = args.value
        try:
            if raw.lower() in ("true", "false"):
                value: Any = raw.lower() == "true"
            elif raw.startswith("[") or raw.startswith("{"):
                value = json.loads(raw)
            elif raw.lstrip("-").isdigit():
                value = int(raw)
            else:
                value = raw
        except (json.JSONDecodeError, ValueError):
            value = raw
        cfg[args.key] = value
        save_config(cfg)
        print_ok("{} = {!r}".format(args.key, value))
        return 0

    if action == "reset":
        if not getattr(args, "yes", False):
            resp = input("¿Restablecer la configuración a valores por defecto? [y/N] ")
            if resp.strip().lower() not in ("y", "yes", "s", "si", "sí"):
                print_info("Cancelado.")
                return 0
        save_config(default_config())
        print_ok("Configuración restablecida.")
        return 0

    if action == "path":
        print(APP_DIR)
        return 0

    return 1


# --------------------------------------------------------------------------- #
# Comando: status
# --------------------------------------------------------------------------- #
def cmd_status(args) -> int:
    ensure_app_dirs()
    cfg = load_config()
    records = load_quarantine_records()
    sigs = load_signatures()
    blocklist = load_url_blocklist()
    history = load_url_history()

    files_in_quarantine = 0
    urls_in_quarantine = 0
    for r in records:
        if r.get("type") == "url":
            urls_in_quarantine += 1
        else:
            files_in_quarantine += 1

    quarantine_size = 0
    if QUARANTINE_DIR.exists():
        for f in QUARANTINE_DIR.glob("*"):
            try:
                if f.is_file():
                    quarantine_size += f.stat().st_size
            except OSError:
                pass

    data = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "platform": "{} {} ({})".format(platform.system(), platform.release(),
                                        platform.machine()),
        "python": sys.version.split()[0],
        "config_path": str(APP_DIR),
        "quarantine_dir": str(QUARANTINE_DIR),
        "signatures": len(sigs),
        "url_blocklist": len(blocklist),
        "url_history": len(history),
        "quarantine_records": len(records),
        "quarantine_files": files_in_quarantine,
        "quarantine_urls": urls_in_quarantine,
        "quarantine_size_human": human_readable_size(quarantine_size),
        "last_scan": cfg.get("last_scan"),
        "scan_history_entries": len(cfg.get("scan_history", [])),
        "url_check_enabled": cfg.get("url_check_enabled", True),
        "url_auto_quarantine": cfg.get("url_auto_quarantine", True),
    }

    if getattr(args, "json", False):
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    print_header("{} — Estado".format(APP_NAME))
    print_kv("Versión:", APP_VERSION, C.CYAN)
    print_kv("Plataforma:", data["platform"])
    print_kv("Python:", data["python"])
    print()
    print_kv("Directorio config:", str(APP_DIR), C.DIM)
    print_kv("Cuarentena:", str(QUARANTINE_DIR), C.DIM)
    print()
    print_kv("Firmas cargadas:", str(data["signatures"]), C.CYAN)
    print_kv("URLs en blocklist:", str(data["url_blocklist"]), C.MAGENTA)
    print_kv("Historial URLs:", str(data["url_history"]), C.DIM)
    print()
    q_color = C.RED if data["quarantine_records"] else C.GREEN
    print_kv("Elementos en cuarentena:", str(data["quarantine_records"]), q_color)
    print_kv("  - archivos:", str(data["quarantine_files"]))
    print_kv("  - URLs:", str(data["quarantine_urls"]))
    print_kv("Tamaño cuarentena:", data["quarantine_size_human"])
    print()
    ls = data["last_scan"]
    if ls:
        print_kv("Último escaneo:", "{} — {}".format(ls.get("tipo"), ls.get("fecha")))
        amen_color = C.RED if ls.get("amenazas") else C.GREEN
        print_kv("  amenazas:", str(ls.get("amenazas", 0)), amen_color)
        print_kv("  archivos:", str(ls.get("escaneados", 0)))
    else:
        print_kv("Último escaneo:", "(ninguno)", C.DIM)
    print()
    uc = C.GREEN if data["url_check_enabled"] else C.YELLOW
    print_kv("URL check:",
             "habilitado" if data["url_check_enabled"] else "deshabilitado", uc)
    uq = C.GREEN if data["url_auto_quarantine"] else C.YELLOW
    print_kv("URL auto-cuarentena:",
             "habilitado" if data["url_auto_quarantine"] else "deshabilitado", uq)
    print()
    return 0


# --------------------------------------------------------------------------- #
# Comando: history
# --------------------------------------------------------------------------- #
def cmd_history(args) -> int:
    ensure_app_dirs()
    cfg = load_config()
    hist = cfg.get("scan_history", [])
    action = getattr(args, "action", None)
    limit = getattr(args, "limit", 0) or 0
    as_json = getattr(args, "json", False)

    if action == "clear":
        if not getattr(args, "yes", False):
            resp = input("¿Borrar el historial de escaneos? [y/N] ").strip().lower()
            if resp not in ("y", "yes", "s", "si", "sí"):
                print_info("Cancelado.")
                return 0
        cfg["scan_history"] = []
        cfg["last_scan"] = None
        save_config(cfg)
        print_ok("Historial borrado.")
        return 0

    if action == "export":
        dest = getattr(args, "path", None) or "history_{}.csv".format(
            datetime.now().strftime("%Y%m%d_%H%M%S"))
        try:
            with open(dest, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["tipo", "fecha", "escaneados", "amenazas",
                            "duracion_seg", "errores", "cancelado"])
                for h in hist:
                    w.writerow([h.get("tipo", ""), h.get("fecha", ""),
                                h.get("escaneados", 0), h.get("amenazas", 0),
                                h.get("duracion_seg", 0), h.get("errores", 0),
                                h.get("cancelado", False)])
            print_ok("Exportado: " + dest)
            return 0
        except OSError as e:
            print_err("Error: " + str(e))
            return 1

    if not hist:
        print_info("Sin escaneos registrados.")
        return 0
    items = hist[-limit:] if limit > 0 else hist
    if as_json:
        print(json.dumps(items, indent=2, ensure_ascii=False))
        return 0
    print_header("Historial ({} entradas, mostrando {})".format(len(hist), len(items)))
    total_files = sum(h.get("escaneados", 0) for h in hist)
    total_threats = sum(h.get("amenazas", 0) for h in hist)
    total_time = sum(h.get("duracion_seg", 0) for h in hist)
    print_kv("Total archivos:", str(total_files))
    print_kv("Total amenazas:", str(total_threats),
             C.RED if total_threats else C.GREEN)
    print_kv("Tiempo acumulado:", "{:.1f}s".format(total_time))
    print()
    for h in reversed(items):
        tipo = str(h.get("tipo", "?"))
        fecha = str(h.get("fecha", "?"))
        amen = h.get("amenazas", 0)
        color = C.RED if amen else C.GREEN
        tipo_col = c("{:<12}".format(tipo), C.BOLD)
        fecha_col = c(fecha, C.DIM)
        amen_col = c(str(amen), color)
        print("  {}  {}  archivos: {:>6}  amenazas: {}  ({}s)".format(
            fecha_col, tipo_col, h.get("escaneados", 0),
            amen_col, h.get("duracion_seg", 0)))
    print()
    return 0


# --------------------------------------------------------------------------- #
# Comando: watch
# --------------------------------------------------------------------------- #
def cmd_watch(args) -> int:
    global _SCAN_CANCEL
    _SCAN_CANCEL = False
    try:
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
    except (ValueError, AttributeError):
        pass

    ensure_app_dirs()
    config = load_config()
    signatures = load_signatures()
    hash_whitelist = load_hash_whitelist()
    max_size_bytes = config.get("max_hash_size_mb", 200) * 1024 * 1024
    quarantine_password = config.get("quarantine_password")

    watch_path = os.path.abspath(args.path)
    if not os.path.isdir(watch_path):
        print_err("No es una carpeta válida: " + watch_path)
        return 1

    interval = max(1, args.interval)
    print_header("Monitoreando: " + watch_path)
    print_info("Intervalo: {}s. Pulsa Ctrl+C para salir.".format(interval))
    print()

    known = {}
    for root_dir, dirs, files in os.walk(watch_path):
        for fname in files:
            fp = os.path.join(root_dir, fname)
            try:
                known[fp] = os.path.getmtime(fp)
            except OSError:
                pass

    quarantine_records = load_quarantine_records()

    while not _SCAN_CANCEL:
        time.sleep(interval)
        try:
            for root_dir, dirs, files in os.walk(watch_path):
                for fname in files:
                    fp = os.path.join(root_dir, fname)
                    try:
                        mtime = os.path.getmtime(fp)
                    except OSError:
                        continue
                    if fp in known and known[fp] == mtime:
                        continue
                    known[fp] = mtime
                    res = _scan_single(fp, max_size_bytes, signatures,
                                       hash_whitelist, config)
                    ts = datetime.now().strftime("%H:%M:%S")
                    if res["threat"]:
                        threat = res["threat"]
                        tag = c("⚠ AMENAZA", C.RED, bold=True)
                        print("  {}  {}  {} → {}".format(
                            c(ts, C.DIM), tag, os.path.basename(fp),
                            threat["name"]))
                        qres = quarantine_move(fp, QUARANTINE_DIR,
                                               password=quarantine_password)
                        if qres:
                            dest, salt = qres
                            quarantine_records.append({
                                "id": uuid.uuid4().hex,
                                "filename": os.path.basename(fp),
                                "original_path": fp,
                                "quarantine_path": dest,
                                "threat_name": threat["name"],
                                "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                                "sha256": (res["hashes"] or {}).get("sha256", ""),
                                "salt": salt.hex(),
                                "type": "file",
                            })
                            save_quarantine_records(quarantine_records)
                    else:
                        tag = c("✓ limpio", C.GREEN)
                        print("  {}  {}     {}".format(
                            c(ts, C.DIM), tag, os.path.basename(fp)))
        except Exception as e:
            print_err("Error durante el monitoreo: " + str(e))

    print()
    print_info("Monitoreo detenido.")
    return 0


# --------------------------------------------------------------------------- #
# Parser principal
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="david_secure_cli.py",
        description="{} CLI v{} — Antivirus educativo".format(APP_NAME, APP_VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplos:\n"
               "  david_secure_cli.py scan rapido\n"
               "  david_secure_cli.py scan custom --path ~/Downloads\n"
               "  david_secure_cli.py url 'http://paypal-login.tk/verify.exe'\n"
               "  david_secure_cli.py status --json\n"
               "  david_secure_cli.py watch ~/Downloads --interval 10\n",
    )
    parser.add_argument("--version", action="version",
                        version="{} CLI {}".format(APP_NAME, APP_VERSION))
    parser.add_argument("--no-color", action="store_true",
                        help="Desactiva la salida con colores ANSI")
    parser.add_argument("--no-banner", action="store_true",
                        help="No muestra el banner ASCII de inicio")
    parser.add_argument("--no-pause", action="store_true",
                        help="No entra en la mini-shell al terminar")
    sub = parser.add_subparsers(dest="cmd", metavar="<comando>")

    # ---- scan ---- #
    p_scan = sub.add_parser("scan", help="Escanea archivos o carpetas")
    p_scan.add_argument("tipo", nargs="?", default="rapido",
                        choices=["rapido", "completo", "custom"],
                        help="Tipo de escaneo (default: rapido)")
    p_scan.add_argument("--path", "-p", help="Ruta personalizada")
    p_scan.add_argument("--json", action="store_true", help="Salida JSON")
    p_scan.add_argument("--quiet", "-q", action="store_true",
                        help="Solo muestra amenazas")
    p_scan.add_argument("--no-quarantine", action="store_true",
                        help="No mover a cuarentena (solo reportar)")
    p_scan.add_argument("--fail-on-threat", action="store_true",
                        help="Devuelve código 2 si encuentra amenazas")
    p_scan.set_defaults(func=cmd_scan)

    # ---- url ---- #
    p_url = sub.add_parser("url", help="Analiza una URL en busca de amenazas")
    p_url.add_argument("url", help="URL a analizar")
    p_url.add_argument("--json", action="store_true", help="Salida JSON")
    p_url.add_argument("--no-block", action="store_true",
                       help="Solo analiza, no añade a blocklist/cuarentena")
    p_url.set_defaults(func=cmd_url)

    # ---- quarantine ---- #
    p_q = sub.add_parser("quarantine", help="Gestiona la cuarentena")
    q_sub = p_q.add_subparsers(dest="action", metavar="<acción>", required=True)

    q_list = q_sub.add_parser("list", help="Lista la cuarentena")
    q_list.add_argument("--json", action="store_true")
    q_list.set_defaults(func=cmd_quarantine)

    q_show = q_sub.add_parser("show", help="Muestra un registro completo")
    q_show.add_argument("id", help="ID (prefijo) o nombre del archivo")
    q_show.add_argument("--json", action="store_true")
    q_show.set_defaults(func=cmd_quarantine)

    q_restore = q_sub.add_parser("restore", help="Restaura un archivo")
    q_restore.add_argument("id")
    q_restore.add_argument("--to", help="Ruta destino (default: ruta original)")
    q_restore.add_argument("--force", action="store_true",
                           help="Sobrescribir si el destino existe")
    q_restore.set_defaults(func=cmd_quarantine)

    q_del = q_sub.add_parser("delete", help="Elimina un elemento permanentemente")
    q_del.add_argument("id")
    q_del.set_defaults(func=cmd_quarantine)

    q_empty = q_sub.add_parser("empty", help="Vacía la cuarentena")
    q_empty.add_argument("--yes", "-y", action="store_true",
                         help="No pedir confirmación")
    q_empty.set_defaults(func=cmd_quarantine)

    q_exp = q_sub.add_parser("export", help="Exporta a CSV")
    q_exp.add_argument("path", nargs="?", help="Ruta de salida")
    q_exp.set_defaults(func=cmd_quarantine)

    # ---- blocklist ---- #
    p_b = sub.add_parser("blocklist", help="Gestiona la lista de URLs bloqueadas")
    b_sub = p_b.add_subparsers(dest="action", metavar="<acción>", required=True)

    b_list = b_sub.add_parser("list", help="Lista las URLs bloqueadas")
    b_list.add_argument("--json", action="store_true")
    b_list.set_defaults(func=cmd_blocklist)

    b_add = b_sub.add_parser("add", help="Añade una URL a la lista")
    b_add.add_argument("url")
    b_add.set_defaults(func=cmd_blocklist)

    b_rm = b_sub.add_parser("remove", help="Quita una URL de la lista")
    b_rm.add_argument("url")
    b_rm.set_defaults(func=cmd_blocklist)

    b_clr = b_sub.add_parser("clear", help="Vacía la lista")
    b_clr.add_argument("--yes", "-y", action="store_true")
    b_clr.set_defaults(func=cmd_blocklist)

    # ---- sigs ---- #
    p_s = sub.add_parser("sigs", help="Gestiona las firmas")
    s_sub = p_s.add_subparsers(dest="action", metavar="<acción>", required=True)

    s_list = s_sub.add_parser("list", help="Lista firmas")
    s_list.add_argument("--json", action="store_true")
    s_list.set_defaults(func=cmd_sigs)

    s_imp = s_sub.add_parser("import", help="Importa firmas desde un JSON")
    s_imp.add_argument("path")
    s_imp.set_defaults(func=cmd_sigs)

    s_upd = s_sub.add_parser("update", help="Actualiza firmas desde una URL")
    s_upd.add_argument("url")
    s_upd.set_defaults(func=cmd_sigs)

    s_add = s_sub.add_parser("add", help="Añade una firma manualmente")
    s_add.add_argument("hash", help="Hash de la firma")
    s_add.add_argument("--name", required=True, help="Nombre de la amenaza")
    s_add.add_argument("--algo", default="sha256",
                       choices=["md5", "sha1", "sha256"])
    s_add.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "test", "unknown"])
    s_add.set_defaults(func=cmd_sigs)

    # ---- config ---- #
    p_c = sub.add_parser("config", help="Ver / editar configuración")
    c_sub = p_c.add_subparsers(dest="action", metavar="<acción>", required=True)

    c_show = c_sub.add_parser("show", help="Muestra toda la configuración")
    c_show.add_argument("--json", action="store_true")
    c_show.set_defaults(func=cmd_config)

    c_get = c_sub.add_parser("get", help="Obtiene una clave")
    c_get.add_argument("key")
    c_get.add_argument("--json", action="store_true")
    c_get.set_defaults(func=cmd_config)

    c_set = c_sub.add_parser("set", help="Establece una clave")
    c_set.add_argument("key")
    c_set.add_argument("value")
    c_set.set_defaults(func=cmd_config)

    c_reset = c_sub.add_parser("reset", help="Restablece a valores por defecto")
    c_reset.add_argument("--yes", "-y", action="store_true")
    c_reset.set_defaults(func=cmd_config)

    c_path = c_sub.add_parser("path", help="Muestra la ruta de config")
    c_path.set_defaults(func=cmd_config)

    # ---- status ---- #
    p_status = sub.add_parser("status", help="Estado del sistema")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    # ---- history ---- #
    p_h = sub.add_parser("history", help="Historial de escaneos")
    p_h.add_argument("--limit", "-n", type=int, default=0,
                     help="Mostrar solo los últimos N (0 = todos)")
    p_h.add_argument("--json", action="store_true")
    p_h.set_defaults(func=cmd_history)
    h_sub = p_h.add_subparsers(dest="subaction", metavar="<acción>")

    h_list = h_sub.add_parser("list", help="Lista el historial")
    h_list.add_argument("--limit", "-n", type=int, default=0)
    h_list.add_argument("--json", action="store_true")
    h_list.set_defaults(func=cmd_history, action="list")

    h_clear = h_sub.add_parser("clear", help="Borra el historial")
    h_clear.add_argument("--yes", "-y", action="store_true")
    h_clear.set_defaults(func=cmd_history, action="clear")

    h_exp = h_sub.add_parser("export", help="Exporta a CSV")
    h_exp.add_argument("path", nargs="?")
    h_exp.set_defaults(func=cmd_history, action="export")

    # ---- watch ---- #
    p_w = sub.add_parser("watch", help="Monitorea una carpeta")
    p_w.add_argument("path", help="Carpeta a monitorear")
    p_w.add_argument("--interval", "-i", type=int, default=5,
                     help="Segundos entre comprobaciones (default: 5)")
    p_w.set_defaults(func=cmd_watch)

    return parser


# --------------------------------------------------------------------------- #
# Mini-shell final
# --------------------------------------------------------------------------- #
def _print_interactive_help() -> None:
    """Ayuda compacta de la mini-shell."""
    print()
    print(c("  Comandos disponibles en la mini-shell:", C.BOLD))
    print()
    subcommands = [
        ("scan", "Escanea archivos/carpetas (rapido | completo | custom)"),
        ("url", "Analiza una URL en busca de amenazas"),
        ("quarantine", "Gestiona la cuarentena (list | restore | delete | empty)"),
        ("blocklist", "Lista de URLs bloqueadas (list | add | remove | clear)"),
        ("sigs", "Firmas (list | import | update | add)"),
        ("config", "Configuración (show | get | set | reset)"),
        ("status", "Estado del sistema"),
        ("history", "Historial de escaneos (list | clear | export)"),
        ("watch", "Monitorea una carpeta (Ctrl+C para detener)"),
    ]
    for name, desc in subcommands:
        name_col = c("{:<12}".format(name), C.CYAN, bold=True)
        print("    " + name_col + c(desc, C.DIM))
    print()
    print("  " + c("Metacomandos:", C.YELLOW, bold=True))
    print("    " + c("{:<12}".format("salir"), C.YELLOW, bold=True) +
          c("Cierra la ventana (también: exit, quit, q)", C.DIM))
    print("    " + c("{:<12}".format("help, ?"), C.YELLOW) + "Muestra esta ayuda")
    print("    " + c("{:<12}".format("clear, cls"), C.YELLOW) + "Limpia la pantalla")
    print("    " + c("{:<12}".format("banner"), C.YELLOW) + "Vuelve a mostrar el logo")
    print()
    print("  " + c("Ejemplos:", C.BOLD))
    print("    " + c("url http://paypal-login.tk/verify.exe", C.GREEN))
    print("    " + c('scan custom --path "./descargas"', C.GREEN))
    print("    " + c("quarantine list", C.GREEN))
    print("    " + c("status --json", C.GREEN))
    print("    " + c("salir", C.GREEN))
    print()


def _interactive_pause(argv: list, force_pause: bool = False,
                       no_pause: bool = False,
                       parser: Optional[argparse.ArgumentParser] = None) -> None:
    """Mini-shell al terminar. Se cierra solo con: salir | exit | quit | q."""
    if no_pause:
        return

    should_pause = force_pause
    if not should_pause:
        # Se activa automáticamente en Windows cuando el script se abre
        # con doble clic (sin argumentos).
        if platform.system() == "Windows" and len(argv) == 0:
            should_pause = True

    if not should_pause:
        return

    if parser is None:
        parser = build_parser()

    print()
    print(c("  Escribe un comando para seguir operando "
            "(ej: help, status, url http://...)",
            C.CYAN, bold=True))
    print(c("  Para cerrar la ventana, escribe: ", C.CYAN) +
          c("salir", C.YELLOW, bold=True) +
          c("   (también: exit, quit, q)", C.DIM))
    print()

    while True:
        try:
            prompt = c("  david-secure> ", C.GREEN, bold=True)
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return

        line = line.strip()
        if not line:
            # Enter en blanco: NO cierra, vuelve a pedir (según petición)
            continue

        low = line.lower()

        # Salidas explícitas SOLO con estas palabras
        if low in ("salir", "exit", "quit", "q"):
            print(c("  Cerrando ventana... ¡hasta pronto!", C.CYAN, bold=True))
            return

        # Ayuda
        if low in ("help", "?", "ayuda", "h"):
            _print_interactive_help()
            continue

        # Limpiar pantalla
        if low in ("clear", "cls"):
            os.system("cls" if platform.system() == "Windows" else "clear")
            continue

        # Repetir banner
        if low in ("banner", "logo"):
            print_banner()
            continue

        # Parsear con shlex (respeta comillas)
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print_err("Error al interpretar la línea: " + str(e))
            continue

        if not parts:
            continue

        # Ejecutar subcomando
        try:
            sub_args = parser.parse_args(parts)
            if not getattr(sub_args, "cmd", None):
                parser.print_help()
                continue
            sub_args.func(sub_args)
        except SystemExit:
            # argparse puede llamar a sys.exit en --help o error; ignoramos
            pass
        except KeyboardInterrupt:
            print()
            print_info("Comando interrumpido.")
        except Exception as e:
            print_err("Error ejecutando el comando: " + str(e))


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main(argv: Optional[list] = None) -> int:
    global _USE_COLOR

    if argv is None:
        argv = sys.argv[1:]

    if "--no-color" in argv:
        _USE_COLOR = False
    elif not sys.stdout.isatty():
        _USE_COLOR = False

    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "no_color", False):
        _USE_COLOR = False

    if not getattr(args, "no_banner", False):
        try:
            print_banner(sys.stderr)
        except Exception:
            pass

    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1

    ensure_app_dirs()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        eprint(c("Interrumpido.", C.YELLOW))
        return 130
    except Exception as e:
        eprint(c("Error inesperado: " + str(e), C.RED))
        return 1


if __name__ == "__main__":
    _argv = sys.argv[1:]
    _no_pause_flag = "--no-pause" in _argv
    _exit_code = 0
    try:
        _exit_code = main(_argv)
    except SystemExit as e:
        _exit_code = e.code if isinstance(e.code, int) else 0
    except KeyboardInterrupt:
        _exit_code = 130
    except Exception as _e:
        eprint(c("Error fatal: " + str(_e), C.RED))
        _exit_code = 1

    try:
        _interactive_pause(_argv, no_pause=_no_pause_flag, force_pause=False)
    except Exception:
        pass

    sys.exit(_exit_code)
