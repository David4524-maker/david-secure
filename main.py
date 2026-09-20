"""
David Secure - Antivirus Engine
================================
Aplicación de escritorio (Tkinter) que simula un motor de antivirus con
funciones reales de escaneo por hash, cuarentena y monitoreo de procesos.

Este archivo es una versión ampliada del proyecto original con mejoras de
robustez, persistencia, usabilidad y rendimiento. Es un proyecto educativo /
de portafolio: no sustituye a una solución antivirus comercial.

Modo GUI:   python david_secure.py
Modo CLI:   python david_secure.py --scan rapido
            python david_secure.py --scan completo --path "/ruta/a/escanear"
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
except ImportError:  # Mejora: no truena la app si falta la dependencia opcional
    psutil = None


# --------------------------------------------------------------------------- #
# Constantes y rutas de la aplicación
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
DOUBLE_EXT_SOSPECHOSAS = (
    ".pdf.exe", ".docx.exe", ".jpg.exe", ".txt.exe", ".png.exe",
    ".xlsx.exe", ".zip.exe", ".mp3.exe", ".pptx.exe",
)
PROCESOS_SOSPECHOSOS_DEFAULT = ["mimikatz.exe", "nc.exe", "netcat.exe", "keylogger.exe"]

HASH_BUFFER_SIZE = 65536

# Paleta de colores: tema claro (original) y tema oscuro (nuevo)
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
# Utilidades puras (sin GUI) — reutilizables también en modo CLI
# --------------------------------------------------------------------------- #
def ensure_app_dirs() -> None:
    """Crea los directorios de configuración, logs y cuarentena si no existen."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def setup_logger() -> logging.Logger:
    """Logger con rotación de archivos (2 MB x 3 backups) en vez de solo consola."""
    logger = logging.getLogger("david_secure")
    if logger.handlers:  # evita handlers duplicados si se llama más de una vez
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "david_secure.log", maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


def human_readable_size(num_bytes: float) -> str:
    """Convierte bytes a una unidad legible (KB, MB, GB...)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def load_json(path: Path, default):
    """Carga JSON de forma resiliente: si el archivo no existe o está corrupto,
    devuelve el valor por defecto en vez de tumbar la aplicación."""
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return default


def save_json(path: Path, data) -> bool:
    """Guardado atómico: escribe a un archivo temporal y luego reemplaza,
    evitando dejar el JSON a medio escribir si el proceso se interrumpe."""
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
        "autoproteccion": False,
        "exclusions": [],
        "max_hash_size_mb": 200,
        "monitor_interval_seconds": 5,
        "process_whitelist": [],
        "last_scan": None,        # dict: {tipo, fecha, escaneados, amenazas, duracion_seg}
        "scan_history": [],       # lista de los últimos escaneos
        "window_geometry": "1100x650",
    }


def load_config() -> dict:
    cfg = default_config()
    cfg.update(load_json(CONFIG_PATH, {}))
    return cfg


def save_config(config: dict) -> None:
    save_json(CONFIG_PATH, config)


def default_signatures() -> list:
    """Firmas de prueba. IMPORTANTE (corrección de bug): el archivo original
    calculaba SHA-256 pero comparaba contra hashes MD5, por lo que la
    detección NUNCA coincidía. Ahora cada firma declara su algoritmo y el
    escáner calcula ambos hashes en una sola pasada por archivo."""
    return [
        {"hash": "44d88612fea8a8f36de82e1278abb02f", "algo": "md5",
         "name": "EICAR Test File (archivo estándar de prueba, no es un virus real)"},
        {"hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0", "algo": "sha256",
         "name": "EICAR Test File (archivo estándar de prueba, no es un virus real)"},
        {"hash": "5d41402abc4b2a76b9719d911017c592", "algo": "md5",
         "name": "Malware.Simulado.1"},
        {"hash": "7d793037a0760186574b0282f2f435e7", "algo": "md5",
         "name": "Trojan.Generic.Test"},
    ]


def load_signatures() -> list:
    sigs = load_json(SIGNATURES_PATH, None)
    if not sigs:
        sigs = default_signatures()
        save_json(SIGNATURES_PATH, sigs)
    return sigs


def merge_signatures_from_file(path: str) -> list:
    """Fusiona firmas externas (JSON) con las firmas ya cargadas, sin duplicar.
    Formato esperado: [{"hash": "...", "algo": "md5"|"sha256", "name": "..."}]"""
    current = load_signatures()
    existing_hashes = {(s["hash"].lower(), s["algo"]) for s in current}
    with open(path, "r", encoding="utf-8") as f:
        nuevas = json.load(f)
    agregadas = 0
    for sig in nuevas:
        key = (sig.get("hash", "").lower(), sig.get("algo", "sha256"))
        if key[0] and key not in existing_hashes:
            current.append({"hash": key[0], "algo": key[1], "name": sig.get("name", "Firma sin nombre")})
            existing_hashes.add(key)
            agregadas += 1
    save_json(SIGNATURES_PATH, current)
    return current, agregadas


def load_quarantine_records() -> list:
    return load_json(QUARANTINE_META_PATH, [])


def save_quarantine_records(records: list) -> None:
    save_json(QUARANTINE_META_PATH, records)


def compute_hashes(filepath: str, max_size_bytes: Optional[int] = None) -> Optional[dict]:
    """Calcula MD5 y SHA-256 en una sola pasada de lectura (antes se hubiera
    necesitado leer el archivo dos veces para comparar contra ambos tipos de
    firma). Devuelve None si el archivo no se puede leer o excede el tamaño
    máximo configurado (para no colgar el escaneo con archivos gigantes)."""
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
    """Compara los hashes calculados contra la base de firmas y devuelve el
    nombre de la amenaza si hay coincidencia."""
    for sig in signatures:
        valor = hashes.get(sig["algo"])
        if valor and valor.lower() == sig["hash"].lower():
            return sig["name"]
    return None


def is_excluded(dirpath: str, exclusions: list) -> bool:
    """Determina si una carpeta debe saltarse (exclusiones del usuario +
    carpetas de sistema conocidas por causar ruido/errores de permisos)."""
    base = os.path.basename(dirpath)
    if base in DEFAULT_EXCLUDED_DIRS:
        return True
    normalized = os.path.normcase(os.path.abspath(dirpath))
    for excl in exclusions:
        if normalized.startswith(os.path.normcase(os.path.abspath(excl))):
            return True
    return False


def quarantine_move(filepath: str, quarantine_dir: Path) -> Optional[str]:
    """Mueve un archivo a cuarentena evitando colisiones de nombre (si ya
    existe un archivo con el mismo nombre, se le agrega un sufijo único)."""
    try:
        filename = os.path.basename(filepath)
        dest = quarantine_dir / filename
        if dest.exists():
            stem, ext = os.path.splitext(filename)
            dest = quarantine_dir / f"{stem}_{uuid.uuid4().hex[:8]}{ext}"
        shutil.move(filepath, str(dest))
        return str(dest)
    except OSError:
        return None


def open_folder_in_explorer(path: str) -> None:
    """Abre una carpeta en el explorador de archivos del sistema operativo."""
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
# Tooltip reutilizable
# --------------------------------------------------------------------------- #
class ToolTip:
    """Pequeño globo de ayuda al pasar el mouse sobre un widget."""

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
        self.logger = setup_logger()

        self.config = load_config()
        self.signatures = load_signatures()
        self.quarantine_dir = QUARANTINE_DIR

        self.autoproteccion_activa = tk.BooleanVar(value=self.config.get("autoproteccion", False))
        self.amenazas_bloqueadas = load_quarantine_records()
        self.log_buffer: list[str] = []   # el log ya no se pierde al cambiar de pestaña
        self.filter_var = tk.StringVar(value="")

        self.state_lock = threading.Lock()
        self.monitoring = self.autoproteccion_activa.get()
        self.monitor_stop_event = threading.Event()   # permite apagar el hilo limpiamente
        self.scan_cancel_event = threading.Event()
        self.scan_running = False

        self.root.title(f"{APP_NAME} - Antivirus Engine  v{APP_VERSION}")
        self.root.geometry(self.config.get("window_geometry", "1100x650"))
        self.root.minsize(900, 550)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Atajos de teclado
        self.root.bind("<F5>", lambda e: self.start_scan("Rápido"))
        self.root.bind("<Control-q>", lambda e: self.on_close())

        self.build_ui()

        if psutil is None:
            self.log("[Aviso] El módulo 'psutil' no está instalado: la protección en "
                      "tiempo real está deshabilitada. Instálalo con: pip install psutil")
        else:
            threading.Thread(target=self.background_monitor, daemon=True).start()

    # ------------------------------------------------------------------- #
    # Construcción / reconstrucción de la interfaz (tema claro/oscuro)
    # ------------------------------------------------------------------- #
    def build_ui(self):
        self.colors = THEMES[self.config.get("theme", "light")]
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.configure(bg=self.colors["bg_main"])

        # --- PANEL IZQUIERDO (Navegación) ---
        self.left_frame = tk.Frame(self.root, bg=self.colors["bg_nav"], width=300)
        self.left_frame.pack(side="left", fill="y")
        self.left_frame.pack_propagate(False)

        self.logo_canvas = tk.Canvas(self.left_frame, width=280, height=100,
                                      bg=self.colors["bg_nav"], highlightthickness=0)
        self.logo_canvas.pack(pady=(20, 0))
        self._draw_logo(self.logo_canvas, canvas_width=280, canvas_height=100)

        # Indicador de estado de protección (punto verde/rojo)
        status_frame = tk.Frame(self.left_frame, bg=self.colors["bg_nav"])
        status_frame.pack(pady=(0, 10))
        self.status_canvas = tk.Canvas(status_frame, width=16, height=16,
                                        bg=self.colors["bg_nav"], highlightthickness=0)
        self.status_canvas.pack(side="left", padx=(0, 6))
        self.status_dot = self.status_canvas.create_oval(2, 2, 14, 14, fill="#FF4D4D", outline="")
        self.status_label = tk.Label(status_frame, text="Desprotegido", bg=self.colors["bg_nav"],
                                      fg=self.colors["fg_text"], font=("Arial", 10))
        self.status_label.pack(side="left")
        self._refresh_status_indicator()

        btn_style = {"bg": self.colors["bg_nav"], "fg": "white", "font": ("Arial", 16),
                     "bd": 0, "anchor": "w", "padx": 20, "cursor": "hand2"}

        nav_items = [
            ("Info  ⓘ", "info", self.colors["accent_info"]),
            ("Seguridad  🛡️", "seguridad", self.colors["accent_seg"]),
            ("Cuentas  👤", "cuentas", self.colors["accent_ok"]),
            ("Dispositivo  🖥️", "dispositivo", "#B3B3B3"),
            ("PROBLEMAS  ❗", "problemas", self.colors["accent_warn"]),
            ("Configuración  ⚙️", "configuracion", "#CCCCCC"),
        ]
        for texto, frame_name, color in nav_items:
            b = tk.Button(self.left_frame, text=texto, command=lambda f=frame_name: self.show_frame(f), **btn_style)
            b.configure(fg=color)
            b.pack(fill="x", pady=10)

        version_lbl = tk.Label(self.left_frame, text=f"v{APP_VERSION}", bg=self.colors["bg_nav"],
                                fg="#8888AA", font=("Arial", 9))
        version_lbl.pack(side="bottom", pady=10)

        # --- PANEL DERECHO (Contenido) ---
        self.right_frame = tk.Frame(self.root, bg=self.colors["bg_main"])
        self.right_frame.pack(side="right", fill="both", expand=True)

        self.content_frame = tk.Frame(self.right_frame, bg=self.colors["bg_main"])
        self.content_frame.pack(fill="both", expand=True, padx=30, pady=20)

        self.show_frame("seguridad")

    def _draw_logo(self, canvas: tk.Canvas, canvas_width: int, canvas_height: int):
        """Dibuja el ícono + 'David' + 'Secure' centrados y sin solaparse.

        Mejora: el original usaba coordenadas de texto fijas (x=80 y x=160)
        que asumían un ancho de letra concreto. Con la fuente Arial Bold de
        28pt, 'David' en realidad mide ~107px y termina en x=187, es decir
        pisa 27px del inicio de 'Secure' en x=160 (se solapan, sobre todo
        notorio en Linux/Mac donde el 'Arial' del sistema puede rendear aún
        más ancho). Aquí se mide el texto real con tkinter.font, se reduce
        el tamaño de fuente si hiciera falta para caber en el ancho
        disponible, y todo el bloque (ícono + texto) se centra en el canvas.
        """
        import tkinter.font as tkfont

        icon_w, icon_h = 40, 60          # mismo tamaño de ícono que el original
        gap_icon_text = 14               # espacio entre el ícono y "David"
        gap_words = 7                    # espacio entre "David" y "Secure"
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
        ix, iy = start_x, (canvas_height - icon_h) / 2  # ícono centrado verticalmente
        text_y = canvas_height / 2

        # Ícono (mismas proporciones que el original, ahora reubicable)
        def m(x, y):
            """Traduce las coordenadas originales (base en x=30,y=20) al
            nuevo origen (ix, iy), conservando la forma exacta del ícono."""
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
            "seguridad": self.build_seguridad,
            "cuentas": self.build_cuentas,
            "dispositivo": self.build_dispositivo,
            "problemas": self.build_problemas,
            "configuracion": self.build_configuracion,
        }
        builders.get(frame_name, self.build_seguridad)()

    # ------------------------------------------------------------------- #
    # Pestaña: Info
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
            f"psutil disponible: {'Sí' if psutil else 'No (protección en tiempo real desactivada)'}",
        ]
        for d in datos:
            tk.Label(self.content_frame, text=d, bg=c["bg_main"], fg=c["fg_text"],
                      font=("Arial", 18)).pack(anchor="w", pady=8)
        tk.Label(self.content_frame, text="Arquitectura: Escaneo por hash (MD5 + SHA-256) y heurística "
                  "de doble extensión", bg=c["bg_main"], fg="#CCFFFF",
                  font=("Arial", 14, "italic")).pack(anchor="w", pady=30)

        tk.Button(self.content_frame, text="Acerca de / Aviso legal", command=self.show_about,
                  bg=c["bg_card"], fg="white", font=("Arial", 12), bd=0, padx=10, pady=6,
                  cursor="hand2").pack(anchor="w")

    def show_about(self):
        top = tk.Toplevel(self.root)
        top.title(f"Acerca de {APP_NAME}")
        top.geometry("480x260")
        top.configure(bg=self.colors["bg_main"])
        texto = (
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "Proyecto educativo / de portafolio que simula un motor de antivirus:\n"
            "escaneo por hash, heurística simple y cuarentena de archivos.\n\n"
            "Este software NO sustituye a una solución antivirus comercial ni "
            "ofrece garantías de detección. Úsalo bajo tu propio riesgo y mantén "
            "siempre actualizado tu antivirus real."
        )
        tk.Label(top, text=texto, bg=self.colors["bg_main"], fg=self.colors["fg_text"],
                  font=("Arial", 11), justify="left", wraplength=440).pack(padx=15, pady=15)
        tk.Button(top, text="Cerrar", command=top.destroy).pack(pady=10)

    # ------------------------------------------------------------------- #
    # Pestaña: Seguridad (escaneo)
    # ------------------------------------------------------------------- #
    def build_seguridad(self):
        c = self.colors
        title_frame = tk.Frame(self.content_frame, bg=c["bg_main"])
        title_frame.pack(fill="x", pady=(0, 15))
        tk.Label(title_frame, text="| Análisis", bg=c["bg_main"], fg=c["fg_title"], font=("Arial", 36)).pack(side="left")
        tk.Label(title_frame, text="🔍", bg=c["bg_main"], fg=c["fg_title"], font=("Arial", 30)).pack(side="left", padx=10)

        btn_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        btn_row.pack(pady=5)

        self.btn_rapido = tk.Button(btn_row, text="Rápido", bg="#5CB85C", fg="white", font=("Arial", 18),
                                     bd=0, width=13, height=2, cursor="hand2",
                                     command=lambda: self.start_scan("Rápido"))
        self.btn_rapido.grid(row=0, column=0, padx=5)
        ToolTip(self.btn_rapido, "Escanea Descargas, Escritorio y Temporales (F5)")

        self.btn_completo = tk.Button(btn_row, text="Completo", bg="black", fg="white", font=("Arial", 18),
                                       bd=0, width=13, height=2, cursor="hand2",
                                       command=lambda: self.start_scan("Completo"))
        self.btn_completo.grid(row=0, column=1, padx=5)
        ToolTip(self.btn_completo, "Escanea toda tu carpeta de usuario (más lento)")

        self.btn_personalizado = tk.Button(btn_row, text="Personalizado", bg="#337AB7", fg="white",
                                            font=("Arial", 18), bd=0, width=13, height=2, cursor="hand2",
                                            command=self.start_custom_scan)
        self.btn_personalizado.grid(row=0, column=2, padx=5)
        ToolTip(self.btn_personalizado, "Elige tú qué carpeta escanear")

        self.btn_stop = tk.Button(self.content_frame, text="⏹ Detener escaneo", bg=c["accent_warn"],
                                   fg="white", font=("Arial", 12), bd=0, padx=10, pady=4,
                                   cursor="hand2", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(pady=8)

        chk_auto = tk.Checkbutton(self.content_frame, text="Dejar que David Secure te proteja automáticamente",
                                   variable=self.autoproteccion_activa, bg=c["bg_main"], fg=c["fg_text"],
                                   font=("Arial", 14), activebackground=c["bg_main"], selectcolor="black",
                                   command=self.toggle_autoproteccion,
                                   state="normal" if psutil else "disabled")
        chk_auto.pack(pady=15, anchor="w")

        info_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        info_row.pack(fill="x", anchor="w")
        tk.Label(info_row, text=f"Firmas cargadas: {len(self.signatures)}", bg=c["bg_main"],
                  fg="#CCFFFF", font=("Arial", 11)).pack(side="left", padx=(0, 20))
        ultimo = self.config.get("last_scan")
        ultimo_txt = "Último escaneo: nunca" if not ultimo else (
            f"Último escaneo: {ultimo['tipo']} el {ultimo['fecha']} "
            f"({ultimo['amenazas']} amenaza(s), {ultimo['escaneados']} archivos)")
        self.lbl_ultimo_scan = tk.Label(info_row, text=ultimo_txt, bg=c["bg_main"], fg="#CCFFFF", font=("Arial", 11))
        self.lbl_ultimo_scan.pack(side="left")

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
            self.log_text.insert("end", "David Secure listo. Esperando instrucciones...\n")
        self.log_text.config(state="disabled")

        btns_log = tk.Frame(self.content_frame, bg=c["bg_main"])
        btns_log.pack(anchor="e", pady=(0, 5))
        tk.Button(btns_log, text="Copiar log", command=self.copy_log_to_clipboard, bg=c["bg_card"],
                  fg="white", bd=0, padx=8, pady=3, cursor="hand2").pack(side="left", padx=4)
        tk.Button(btns_log, text="Exportar reporte", command=self.export_report, bg=c["bg_card"],
                  fg="white", bd=0, padx=8, pady=3, cursor="hand2").pack(side="left", padx=4)

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
                                             filetypes=[("Archivo de texto", "*.txt")],
                                             initialfile="david_secure_reporte.txt")
        if not ruta:
            return
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(f"Reporte {APP_NAME} v{APP_VERSION} - {datetime.now().isoformat(timespec='seconds')}\n")
                f.write("=" * 60 + "\n\n")
                f.write("\n".join(self.log_buffer))
                f.write("\n\nAmenazas en cuarentena:\n")
                for r in self.amenazas_bloqueadas:
                    f.write(f" - {r.get('filename')} | {r.get('threat_name')} | {r.get('date')}\n")
            messagebox.showinfo(APP_NAME, f"Reporte guardado en:\n{ruta}")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"No se pudo guardar el reporte: {e}")

    # ------------------------------------------------------------------- #
    # Pestaña: Cuentas
    # ------------------------------------------------------------------- #
    def build_cuentas(self):
        c = self.colors
        tk.Label(self.content_frame, text="Seguridad de Cuentas", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 10))
        tk.Label(self.content_frame, text="(Datos de demostración — no se conecta a servicios reales)",
                  bg=c["bg_main"], fg="#CCFFFF", font=("Arial", 11, "italic")).pack(anchor="w", pady=(0, 15))
        cuentas = [("Correo Electrónico", "Seguro", c["accent_ok"]),
                   ("Redes Sociales", "Contraseña Filtrada", c["accent_warn"]),
                   ("Banca en Línea", "Seguro (2FA)", c["accent_ok"])]
        for cuenta, estado, color in cuentas:
            frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
            frame.pack(fill="x", pady=5)
            tk.Label(frame, text=cuenta, bg=c["bg_card"], fg=c["fg_text"], font=("Arial", 16)).pack(side="left")
            tk.Label(frame, text=estado, bg=c["bg_card"], fg=color, font=("Arial", 16, "bold")).pack(side="right")

    # ------------------------------------------------------------------- #
    # Pestaña: Dispositivo
    # ------------------------------------------------------------------- #
    def build_dispositivo(self):
        c = self.colors
        tk.Label(self.content_frame, text="Seguridad del Dispositivo", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 20))

        info = [("Sistema Operativo", platform.system()), ("Núcleo", platform.release()),
                ("Arquitectura", platform.machine()), ("Carpeta de Cuarentena", str(self.quarantine_dir))]
        if psutil:
            info.append(("Uso de CPU", f"{psutil.cpu_percent(interval=0.2)} %"))
            info.append(("Uso de RAM", f"{psutil.virtual_memory().percent} %"))
        tam_cuarentena = sum(f.stat().st_size for f in self.quarantine_dir.glob("*") if f.is_file())
        info.append(("Tamaño de cuarentena", human_readable_size(tam_cuarentena)))
        info.append(("Archivos en cuarentena", str(len(self.amenazas_bloqueadas))))

        for item, valor in info:
            frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
            frame.pack(fill="x", pady=5)
            tk.Label(frame, text=item, bg=c["bg_card"], fg=c["fg_text"], font=("Arial", 16)).pack(side="left")
            tk.Label(frame, text=valor, bg=c["bg_card"], fg=c["accent_ok"], font=("Arial", 14, "bold")).pack(side="right")

        tk.Button(self.content_frame, text="Abrir carpeta de cuarentena",
                  command=lambda: open_folder_in_explorer(str(self.quarantine_dir)),
                  bg=c["bg_card"], fg="white", bd=0, padx=10, pady=6, cursor="hand2").pack(anchor="w", pady=15)

    # ------------------------------------------------------------------- #
    # Pestaña: Problemas / Cuarentena
    # ------------------------------------------------------------------- #
    def build_problemas(self):
        c = self.colors
        tk.Label(self.content_frame, text="Amenazas Bloqueadas / Cuarentena", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 15))

        top_row = tk.Frame(self.content_frame, bg=c["bg_main"])
        top_row.pack(fill="x", pady=(0, 10))
        tk.Label(top_row, text="Buscar:", bg=c["bg_main"], fg=c["fg_text"], font=("Arial", 12)).pack(side="left")
        entry = tk.Entry(top_row, textvariable=self.filter_var, font=("Arial", 12), width=30)
        entry.pack(side="left", padx=8)
        entry.bind("<KeyRelease>", lambda e: self.show_frame("problemas"))
        tk.Button(top_row, text="Vaciar cuarentena", command=self.vaciar_cuarentena, bg=c["accent_warn"],
                  fg="white", bd=0, padx=10, pady=4, cursor="hand2").pack(side="right")

        filtro = self.filter_var.get().lower().strip()
        registros = [r for r in self.amenazas_bloqueadas if filtro in r.get("filename", "").lower()] \
            if filtro else self.amenazas_bloqueadas

        if not registros:
            tk.Label(self.content_frame, text="No hay amenazas detectadas.", bg=c["bg_main"], fg=c["fg_text"],
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

        for registro in registros:
            frame = tk.Frame(scroll_frame, bg=c["accent_warn"], pady=8, padx=10)
            frame.pack(fill="x", pady=4)
            texto = f"⚠️  {registro.get('filename')} — {registro.get('threat_name')} ({registro.get('date', '')})"
            tk.Label(frame, text=texto, bg=c["accent_warn"], fg="white", font=("Arial", 12),
                      anchor="w").pack(side="left", fill="x", expand=True)
            tk.Button(frame, text="Restaurar", command=lambda r=registro: self.restore_from_quarantine(r),
                      bg="white", fg="black", bd=0, padx=6, cursor="hand2").pack(side="right", padx=4)
            tk.Button(frame, text="Eliminar", command=lambda r=registro: self.delete_permanently(r),
                      bg="black", fg="white", bd=0, padx=6, cursor="hand2").pack(side="right", padx=4)

    def restore_from_quarantine(self, registro: dict):
        origen = registro.get("quarantine_path")
        destino = registro.get("original_path")
        if not origen or not os.path.exists(origen):
            messagebox.showerror(APP_NAME, "El archivo en cuarentena ya no existe.")
            return
        if not messagebox.askyesno(APP_NAME, f"¿Restaurar '{registro.get('filename')}' a su ubicación original?\n"
                                              "Esto puede ser riesgoso si el archivo era una amenaza real."):
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

    def delete_permanently(self, registro: dict):
        if not messagebox.askyesno(APP_NAME, f"¿Eliminar permanentemente '{registro.get('filename')}'?"):
            return
        origen = registro.get("quarantine_path")
        try:
            if origen and os.path.exists(origen):
                os.remove(origen)
        except OSError as e:
            messagebox.showerror(APP_NAME, f"No se pudo eliminar: {e}")
            return
        self.amenazas_bloqueadas = [r for r in self.amenazas_bloqueadas if r is not registro]
        save_quarantine_records(self.amenazas_bloqueadas)
        self.log(f"Archivo eliminado permanentemente: {registro.get('filename')}")
        self.show_frame("problemas")

    def vaciar_cuarentena(self):
        if not self.amenazas_bloqueadas:
            return
        if not messagebox.askyesno(APP_NAME, "¿Eliminar TODOS los archivos en cuarentena de forma permanente?"):
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
        self.log("Cuarentena vaciada por el usuario.")
        self.show_frame("problemas")

    # ------------------------------------------------------------------- #
    # Pestaña: Configuración (nueva)
    # ------------------------------------------------------------------- #
    def build_configuracion(self):
        c = self.colors
        tk.Label(self.content_frame, text="Configuración", bg=c["bg_main"], fg=c["fg_text"],
                  font=("Arial", 32, "bold")).pack(anchor="w", pady=(0, 20))

        # Tema
        tema_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        tema_frame.pack(fill="x", pady=6)
        tk.Label(tema_frame, text="Tema visual", bg=c["bg_card"], fg=c["fg_text"], font=("Arial", 14)).pack(side="left")
        tk.Button(tema_frame, text="Alternar claro/oscuro", command=self.toggle_theme, bg="white", fg="black",
                  bd=0, padx=10, pady=4, cursor="hand2").pack(side="right")

        # Exclusiones
        excl_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        excl_frame.pack(fill="x", pady=6)
        tk.Label(excl_frame, text="Carpetas excluidas del escaneo:", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 14)).pack(anchor="w")
        self.excl_listbox = tk.Listbox(excl_frame, height=4, font=("Consolas", 10))
        self.excl_listbox.pack(fill="x", pady=5)
        for e in self.config.get("exclusions", []):
            self.excl_listbox.insert("end", e)
        btns = tk.Frame(excl_frame, bg=c["bg_card"])
        btns.pack(anchor="e")
        tk.Button(btns, text="Agregar carpeta", command=self.add_exclusion, bg="white", fg="black",
                  bd=0, padx=8, cursor="hand2").pack(side="left", padx=4)
        tk.Button(btns, text="Quitar seleccionada", command=self.remove_exclusion, bg="white", fg="black",
                  bd=0, padx=8, cursor="hand2").pack(side="left", padx=4)

        # Firmas
        sig_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        sig_frame.pack(fill="x", pady=6)
        tk.Label(sig_frame, text=f"Firmas cargadas: {len(self.signatures)}", bg=c["bg_card"], fg=c["fg_text"],
                  font=("Arial", 14)).pack(side="left")
        tk.Button(sig_frame, text="Importar firmas (JSON)", command=self.import_signatures, bg="white",
                  fg="black", bd=0, padx=10, pady=4, cursor="hand2").pack(side="right")

        # Límite de tamaño de archivo
        size_frame = tk.Frame(self.content_frame, bg=c["bg_card"], pady=10, padx=10)
        size_frame.pack(fill="x", pady=6)
        tk.Label(size_frame, text="Tamaño máximo de archivo a analizar (MB):", bg=c["bg_card"],
                  fg=c["fg_text"], font=("Arial", 14)).pack(side="left")
        self.max_size_var = tk.IntVar(value=self.config.get("max_hash_size_mb", 200))
        tk.Spinbox(size_frame, from_=10, to=5000, increment=10, textvariable=self.max_size_var,
                   width=8, command=self.save_max_size).pack(side="right")

        # Otras acciones
        acciones_frame = tk.Frame(self.content_frame, bg=c["bg_main"])
        acciones_frame.pack(fill="x", pady=15)
        tk.Button(acciones_frame, text="Vaciar logs", command=self.clear_logs, bg=c["bg_card"], fg="white",
                  bd=0, padx=10, pady=6, cursor="hand2").pack(side="left", padx=5)
        tk.Button(acciones_frame, text="Restablecer configuración", command=self.reset_config, bg=c["accent_warn"],
                  fg="white", bd=0, padx=10, pady=6, cursor="hand2").pack(side="left", padx=5)

    def toggle_theme(self):
        self.config["theme"] = "dark" if self.config.get("theme") == "light" else "light"
        save_config(self.config)
        self.build_ui()
        self.show_frame("configuracion")

    def add_exclusion(self):
        carpeta = filedialog.askdirectory(title="Selecciona carpeta a excluir del escaneo")
        if carpeta:
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
        ruta = filedialog.askopenfilename(title="Selecciona archivo de firmas JSON",
                                           filetypes=[("JSON", "*.json")])
        if not ruta:
            return
        try:
            self.signatures, agregadas = merge_signatures_from_file(ruta)
            messagebox.showinfo(APP_NAME, f"Se importaron {agregadas} firma(s) nueva(s).")
            self.show_frame("configuracion")
        except (OSError, json.JSONDecodeError, KeyError) as e:
            messagebox.showerror(APP_NAME, f"No se pudo importar el archivo de firmas: {e}")

    def save_max_size(self):
        self.config["max_hash_size_mb"] = self.max_size_var.get()
        save_config(self.config)

    def clear_logs(self):
        if messagebox.askyesno(APP_NAME, "¿Vaciar el historial de logs en pantalla?"):
            self.log_buffer.clear()
            self.show_frame("seguridad")

    def reset_config(self):
        if messagebox.askyesno(APP_NAME, "¿Restablecer toda la configuración a los valores por defecto?"):
            self.config = default_config()
            save_config(self.config)
            self.build_ui()

    # ------------------------------------------------------------------- #
    # Lógica de protección en tiempo real
    # ------------------------------------------------------------------- #
    def _refresh_status_indicator(self):
        color = self.colors["accent_ok"] if self.monitoring else self.colors["accent_warn"]
        texto = "Protegido" if self.monitoring else "Desprotegido"
        self.status_canvas.itemconfig(self.status_dot, fill=color)
        self.status_label.config(text=texto)

    def toggle_autoproteccion(self):
        self.config["autoproteccion"] = self.autoproteccion_activa.get()
        save_config(self.config)
        if self.autoproteccion_activa.get():
            with self.state_lock:
                self.monitoring = True
            messagebox.showinfo(APP_NAME, "Protección automática ACTIVADA.\nMonitoreando procesos en segundo plano.")
        else:
            with self.state_lock:
                self.monitoring = False
            messagebox.showwarning(APP_NAME, "Protección automática DESACTIVADA.")
        self._refresh_status_indicator()

    def log(self, mensaje: str):
        self.logger.info(mensaje)
        self.log_buffer.append(mensaje)
        try:
            self.root.after(0, self._update_log, mensaje)
        except RuntimeError:
            pass  # la ventana ya se cerró

    def _update_log(self, mensaje: str):
        # Mejora: valida que el widget exista antes de escribir (evita crashear
        # si el usuario cambió de pestaña justo cuando llega un mensaje del hilo).
        if not hasattr(self, "log_text") or not self.log_text.winfo_exists():
            return
        self.log_text.config(state="normal")
        self.log_text.insert("end", mensaje + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _set_scan_buttons_state(self, state: str):
        for btn in (getattr(self, "btn_rapido", None), getattr(self, "btn_completo", None),
                    getattr(self, "btn_personalizado", None)):
            if btn is not None and btn.winfo_exists():
                btn.config(state=state)
        if hasattr(self, "btn_stop") and self.btn_stop.winfo_exists():
            self.btn_stop.config(state="normal" if state == "disabled" else "disabled")

    def stop_scan(self):
        self.scan_cancel_event.set()
        self.log("Cancelación solicitada por el usuario...")

    def start_scan(self, tipo: str, custom_path: Optional[str] = None):
        if self.scan_running:
            messagebox.showwarning(APP_NAME, "Ya hay un escaneo en curso.")
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
        threading.Thread(target=self.run_real_scan, args=(tipo, custom_path), daemon=True).start()

    def run_real_scan(self, tipo: str, custom_path: Optional[str] = None):
        try:
            self._run_real_scan_inner(tipo, custom_path)
        except Exception as e:  # Mejora: un error inesperado ya no deja el hilo muerto en silencio
            self.log(f"[Error inesperado durante el escaneo] {e}")
            self.logger.exception("Error inesperado durante el escaneo")
        finally:
            self.scan_running = False
            self.root.after(0, self._on_scan_finished)

    def _on_scan_finished(self):
        self._set_scan_buttons_state("normal")
        if hasattr(self, "progress") and self.progress.winfo_exists():
            self.progress.stop()

    def _run_real_scan_inner(self, tipo: str, custom_path: Optional[str] = None):
        inicio = time.time()
        self.log(f"Iniciando Análisis {tipo}...")
        time.sleep(0.3)

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
        max_size_bytes = self.config.get("max_hash_size_mb", 200) * 1024 * 1024

        archivos_escaneados = 0
        amenazas_encontradas = 0
        omitidos_grandes = 0
        errores = 0
        cancelado = False
        last_update = time.time()

        for ruta in rutas:
            if not os.path.exists(ruta):
                continue
            self.log(f"Escaneando: {ruta}...")

            for root_dir, dirs, files in os.walk(ruta, followlinks=False):
                if self.scan_cancel_event.is_set():
                    cancelado = True
                    break
                # Mejora: se podan las carpetas excluidas antes de entrar (más rápido
                # y evita errores de permisos en carpetas de sistema)
                dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root_dir, d), exclusions)]

                for file in files:
                    if self.scan_cancel_event.is_set():
                        cancelado = True
                        break
                    filepath = os.path.join(root_dir, file)
                    archivos_escaneados += 1

                    try:
                        hashes = compute_hashes(filepath, max_size_bytes)
                        if hashes is None:
                            if os.path.exists(filepath) and os.path.getsize(filepath) > max_size_bytes:
                                omitidos_grandes += 1
                            else:
                                errores += 1
                        else:
                            nombre_malware = match_signature(hashes, self.signatures)
                            if nombre_malware:
                                self.log(f"¡ALERTA! Malware detectado: {file}")
                                self.log(f"Firma: {nombre_malware}")
                                registro = self._poner_en_cuarentena(filepath, nombre_malware, hashes)
                                if registro:
                                    self.log("Archivo puesto en cuarentena con éxito.")
                                    amenazas_encontradas += 1
                                else:
                                    self.log(f"Error al mover a cuarentena: {file}")

                        if file.lower().endswith(DOUBLE_EXT_SOSPECHOSAS):
                            self.log(f"¡ALERTA! Archivo con doble extensión sospechosa: {file}")
                            registro = self._poner_en_cuarentena(filepath, "Doble Extensión", hashes or {})
                            if registro:
                                amenazas_encontradas += 1
                    except Exception:
                        errores += 1  # un archivo problemático no debe tumbar todo el escaneo

                    if archivos_escaneados % 100 == 0 and time.time() - last_update > 0.3:
                        self.log(f"Archivos analizados: {archivos_escaneados}...")
                        last_update = time.time()

                if cancelado:
                    break
            if cancelado:
                break

        duracion = round(time.time() - inicio, 1)
        self.log("----------------------------------------")
        if cancelado:
            self.log(f"Análisis {tipo} CANCELADO por el usuario.")
        else:
            self.log(f"Análisis {tipo} finalizado.")
        self.log(f"Archivos escaneados: {archivos_escaneados}")
        self.log(f"Amenazas neutralizadas: {amenazas_encontradas}")
        if omitidos_grandes:
            self.log(f"Archivos omitidos por tamaño: {omitidos_grandes}")
        if errores:
            self.log(f"Archivos con errores de lectura/permisos: {errores}")
        self.log(f"Duración: {duracion} s")

        if amenazas_encontradas == 0 and not cancelado:
            self.log("El sistema está limpio.")

        resumen = {"tipo": tipo, "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
                   "escaneados": archivos_escaneados, "amenazas": amenazas_encontradas,
                   "duracion_seg": duracion, "cancelado": cancelado}
        self.config["last_scan"] = resumen
        historial = self.config.setdefault("scan_history", [])
        historial.append(resumen)
        self.config["scan_history"] = historial[-20:]  # conserva solo los últimos 20
        save_config(self.config)

        if not cancelado:
            self.root.after(0, lambda: messagebox.showinfo(
                APP_NAME, f"Análisis {tipo} completado.\nAmenazas encontradas: {amenazas_encontradas}"))

    def _poner_en_cuarentena(self, filepath: str, nombre_amenaza: str, hashes: dict) -> Optional[dict]:
        """Mueve el archivo y guarda metadatos para poder restaurarlo después."""
        original_path = filepath
        dest = quarantine_move(filepath, self.quarantine_dir)
        if not dest:
            return None
        registro = {
            "id": uuid.uuid4().hex,
            "filename": os.path.basename(filepath),
            "original_path": original_path,
            "quarantine_path": dest,
            "threat_name": nombre_amenaza,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "sha256": hashes.get("sha256", ""),
        }
        with self.state_lock:
            self.amenazas_bloqueadas.append(registro)
            save_quarantine_records(self.amenazas_bloqueadas)
        return registro

    def background_monitor(self):
        """Monitoreo en tiempo real de procesos sospechosos (hilo daemon,
        pero ahora se puede detener limpiamente con monitor_stop_event)."""
        procesos_sospechosos = set(PROCESOS_SOSPECHOSOS_DEFAULT) - set(self.config.get("process_whitelist", []))
        ultimo_aviso = 0.0

        while not self.monitor_stop_event.is_set():
            if self.monitoring and psutil:
                for proc in psutil.process_iter(["name"]):
                    try:
                        proc_name = (proc.info["name"] or "").lower()
                        if proc_name in procesos_sospechosos and time.time() - ultimo_aviso > 10:
                            self.log(f"¡BLOQUEO EN TIEMPO REAL! Proceso sospechoso detectado: {proc_name}")
                            self.root.after(0, lambda p=proc_name: messagebox.showwarning(
                                APP_NAME, f"¡Amenaza en tiempo real!\nSe detectó el proceso: {p}"))
                            ultimo_aviso = time.time()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
            self.monitor_stop_event.wait(self.config.get("monitor_interval_seconds", 5))

    # ------------------------------------------------------------------- #
    # Cierre de la aplicación
    # ------------------------------------------------------------------- #
    def on_close(self):
        if self.scan_running and not messagebox.askyesno(
                APP_NAME, "Hay un escaneo en curso. ¿Deseas cerrar de todas formas?"):
            return
        self.scan_cancel_event.set()
        self.monitor_stop_event.set()
        self.config["window_geometry"] = self.root.geometry()
        save_config(self.config)
        self.root.destroy()


# --------------------------------------------------------------------------- #
# Modo CLI (sin interfaz gráfica) — útil para automatizar escaneos
# --------------------------------------------------------------------------- #
def run_cli_scan(tipo: str, custom_path: Optional[str], logger: logging.Logger) -> int:
    ensure_app_dirs()
    config = load_config()
    signatures = load_signatures()
    exclusions = config.get("exclusions", [])
    max_size_bytes = config.get("max_hash_size_mb", 200) * 1024 * 1024
    quarantine_records = load_quarantine_records()

    user_home = os.path.expanduser("~")
    if custom_path:
        rutas = [custom_path]
    elif tipo == "rapido":
        rutas = [os.path.join(user_home, "Downloads"), os.path.join(user_home, "Desktop")]
    else:
        rutas = [user_home]

    print(f"{APP_NAME} v{APP_VERSION} — escaneo en modo CLI ({tipo})")
    archivos, amenazas = 0, 0
    inicio = time.time()

    for ruta in rutas:
        if not os.path.exists(ruta):
            continue
        for root_dir, dirs, files in os.walk(ruta, followlinks=False):
            dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root_dir, d), exclusions)]
            for file in files:
                filepath = os.path.join(root_dir, file)
                archivos += 1
                hashes = compute_hashes(filepath, max_size_bytes)
                nombre = match_signature(hashes, signatures) if hashes else None
                # Mejora: la heurística de doble extensión ahora corre también en
                # modo CLI (antes solo existía en la GUI, comportamiento inconsistente)
                if not nombre and file.lower().endswith(DOUBLE_EXT_SOSPECHOSAS):
                    nombre = "Doble Extensión"
                if nombre:
                    dest = quarantine_move(filepath, QUARANTINE_DIR)
                    if dest:
                        quarantine_records.append({
                            "id": uuid.uuid4().hex, "filename": file, "original_path": filepath,
                            "quarantine_path": dest, "threat_name": nombre,
                            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "sha256": (hashes or {}).get("sha256", ""),
                        })
                        amenazas += 1
                        print(f"  [!] {file} -> {nombre} (cuarentena)")
                        logger.info(f"CLI: {file} -> {nombre} (cuarentena)")
                if archivos % 500 == 0:
                    print(f"  ... {archivos} archivos analizados")

    save_quarantine_records(quarantine_records)
    duracion = round(time.time() - inicio, 1)
    config["last_scan"] = {"tipo": tipo, "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "escaneados": archivos, "amenazas": amenazas, "duracion_seg": duracion,
                            "cancelado": False}
    save_config(config)
    print(f"Listo. Archivos: {archivos} | Amenazas: {amenazas} | Duración: {duracion}s")
    return 0


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--scan", choices=["rapido", "completo"],
                         help="Ejecuta un escaneo sin abrir la interfaz gráfica")
    parser.add_argument("--path", help="Ruta personalizada a escanear en modo CLI")
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
