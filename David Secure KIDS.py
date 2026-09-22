import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
import random
import os
import hashlib
import platform
import shutil
import json

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ==================== CONFIGURACIÓN ====================
PARENTAL_PIN = "1234"  # Cambia este PIN para uso real
QUARANTINE_DIR = os.path.join(os.path.expanduser("~"), "DavidSecure_Quarantine")
MANIFEST_FILE = os.path.join(QUARANTINE_DIR, "manifest.json")
# ========================================================


class DavidSecureKidsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("David Secure KIDS")
        self.root.geometry("800x750")
        self.root.configure(bg="#FFD1DC")
        self.root.resizable(False, False)

        self.lang = "es"
        self.is_scanning = False
        self.current_view = "kids"

        # Estado del escaneo real
        self.threats_found = []   # Lista de dicts: {"path": ..., "reason": ...}
        self.suspicious_found = []

        # Asegurar carpeta de cuarentena
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        # --- TEXTOS BILINGÜES ---
        self.texts = {
            "es": {
                "app_title": "🛡️ David Secure KIDS 🛡️",
                "app_subtitle": "¡Tu superhéroe contra los virus!",
                "tab_kids": "🎮 Modo KIDS",
                "tab_real": "🔬 Modo Real",
                "btn_scan": "¡ESCANEAR AHORA!",
                "btn_real_scan": "🔍 ESCANEAR MI PC DE VERDAD",
                "btn_quarantine": "🦠 Mover a Cuarentena",
                "btn_restore": "♻️ Restaurar archivos",
                "btn_scanning": "Escaneando...",
                "status_ready": "Presiona el botón para empezar.",
                "status_scanning": "Buscando virus malos...",
                "status_clean": "¡Felicidades! Tu computadora está 100% limpia.",
                "status_found": "¡Atrapamos un virus! Pero es de juguete, no pasa nada.",
                "status_real_ready": "Modo Real: Analizaremos tu PC sin borrar nada.",
                "status_real_scanning": "Analizando archivos reales de tu PC...",
                "status_real_done": "Análisis completado. Revisa el reporte abajo.",
                "progress": "Progreso:",
                "history_kids": "Historial de amenazas atrapadas:",
                "history_real": "📋 Reporte del Análisis Real:",
                "lang_btn": "English 🇺🇸",
                "warning_title": "Aviso de Seguridad",
                "warning_msg": "El Modo Real analiza archivos de verdad pero NO borra nada.\n\nSolo reporta lo que encuentra para que aprendas.\n\n¿Quieres continuar?",
                "real_no_psutil": "(Aviso: psutil no está instalado, se omitirá el análisis de procesos)",
                "real_folders": "Carpetas a analizar:",
                "real_files": "Archivos escaneados:",
                "real_threats": "Amenazas encontradas:",
                "real_clean": "No se encontraron amenazas. ¡Tu PC está limpia!",
                "real_suspicious": "Archivos sospechosos encontrados:",
                "real_processes": "Procesos en ejecución analizados:",
                "real_process_alert": "⚠️ Proceso sospechoso detectado:",
                "real_eicar": "🧪 Archivo de prueba EICAR detectado en:",
                "pin_title": "Autorización Parental",
                "pin_msg": "Introduce el PIN de padre/tutor para mover archivos a la cuarentena:",
                "pin_wrong": "❌ PIN incorrecto. Acción cancelada.",
                "quarantine_confirm_title": "Confirmar Cuarentena",
                "quarantine_confirm_msg": "Se moverán {n} archivo(s) a la carpeta de cuarentena.\n\n¿Estás seguro?",
                "quarantine_none": "No hay amenazas para mover a cuarentena.",
                "quarantine_done": "✅ {n} archivo(s) movido(s) a cuarentena.",
                "quarantine_error": "⚠️ No se pudo mover: {file}",
                "restore_confirm_title": "Restaurar Archivos",
                "restore_confirm_msg": "Se restaurarán {n} archivo(s) desde la cuarentena a su ubicación original.\n\n¿Estás seguro?",
                "restore_none": "La cuarentena está vacía.",
                "restore_done": "✅ {n} archivo(s) restaurado(s).",
                "restore_error": "⚠️ No se pudo restaurar: {file}",
                "quarantine_folder": "📂 Carpeta de cuarentena:",
                "quarantine_moved": "🦠 En cuarentena: {file}",
                "quarantine_manifest": "Manifest guardado correctamente."
            },
            "en": {
                "app_title": "🛡️ David Secure KIDS 🛡️",
                "app_subtitle": "Your superhero against viruses!",
                "tab_kids": "🎮 KIDS Mode",
                "tab_real": "🔬 Real Mode",
                "btn_scan": "SCAN NOW!",
                "btn_real_scan": "🔍 REALLY SCAN MY PC",
                "btn_quarantine": "🦠 Move to Quarantine",
                "btn_restore": "♻️ Restore files",
                "btn_scanning": "Scanning...",
                "status_ready": "Press the button to start.",
                "status_scanning": "Looking for bad viruses...",
                "status_clean": "Congratulations! Your computer is 100% clean.",
                "status_found": "We caught a virus! But it's a toy one, don't worry.",
                "status_real_ready": "Real Mode: We'll scan your PC without deleting anything.",
                "status_real_scanning": "Analyzing real files on your PC...",
                "status_real_done": "Scan completed. Check the report below.",
                "progress": "Progress:",
                "history_kids": "Caught threat history:",
                "history_real": "📋 Real Scan Report:",
                "lang_btn": "Español 🇲🇽",
                "warning_title": "Security Notice",
                "warning_msg": "Real Mode analyzes real files but does NOT delete anything.\n\nIt only reports what it finds so you can learn.\n\nDo you want to continue?",
                "real_no_psutil": "(Note: psutil is not installed, process analysis will be skipped)",
                "real_folders": "Folders to analyze:",
                "real_files": "Files scanned:",
                "real_threats": "Threats found:",
                "real_clean": "No threats found. Your PC is clean!",
                "real_suspicious": "Suspicious files found:",
                "real_processes": "Running processes analyzed:",
                "real_process_alert": "⚠️ Suspicious process detected:",
                "real_eicar": "🧪 EICAR test file detected in:",
                "pin_title": "Parental Authorization",
                "pin_msg": "Enter parent/guardian PIN to move files to quarantine:",
                "pin_wrong": "❌ Wrong PIN. Action cancelled.",
                "quarantine_confirm_title": "Confirm Quarantine",
                "quarantine_confirm_msg": "{n} file(s) will be moved to the quarantine folder.\n\nAre you sure?",
                "quarantine_none": "No threats to move to quarantine.",
                "quarantine_done": "✅ {n} file(s) moved to quarantine.",
                "quarantine_error": "⚠️ Could not move: {file}",
                "restore_confirm_title": "Restore Files",
                "restore_confirm_msg": "{n} file(s) will be restored from quarantine to their original location.\n\nAre you sure?",
                "restore_none": "Quarantine is empty.",
                "restore_done": "✅ {n} file(s) restored.",
                "restore_error": "⚠️ Could not restore: {file}",
                "quarantine_folder": "📂 Quarantine folder:",
                "quarantine_moved": "🦠 Quarantined: {file}",
                "quarantine_manifest": "Manifest saved successfully."
            }
        }

        # Variables dinámicas
        self.var_app_title = tk.StringVar()
        self.var_app_subtitle = tk.StringVar()
        self.var_tab_kids = tk.StringVar()
        self.var_tab_real = tk.StringVar()
        self.var_btn_scan = tk.StringVar()
        self.var_btn_real_scan = tk.StringVar()
        self.var_btn_quarantine = tk.StringVar()
        self.var_btn_restore = tk.StringVar()
        self.var_status = tk.StringVar()
        self.var_progress = tk.StringVar()
        self.var_history = tk.StringVar()
        self.var_lang_btn = tk.StringVar()

        self.update_texts()
        self.build_ui()
        self.switch_view("kids")

    # ---------- IDIOMA ----------
    def update_texts(self):
        t = self.texts[self.lang]
        self.var_app_title.set(t["app_title"])
        self.var_app_subtitle.set(t["app_subtitle"])
        self.var_tab_kids.set(t["tab_kids"])
        self.var_tab_real.set(t["tab_real"])
        self.var_btn_scan.set(t["btn_scan"])
        self.var_btn_real_scan.set(t["btn_real_scan"])
        self.var_btn_quarantine.set(t["btn_quarantine"])
        self.var_btn_restore.set(t["btn_restore"])
        self.var_progress.set(t["progress"])
        self.var_lang_btn.set(t["lang_btn"])
        
        if self.current_view == "kids":
            self.var_status.set(t["status_ready"])
            self.var_history.set(t["history_kids"])
        else:
            self.var_status.set(t["status_real_ready"])
            self.var_history.set(t["history_real"])

    def change_language(self):
        self.lang = "en" if self.lang == "es" else "es"
        self.update_texts()
        self.refresh_history_view()

    # ---------- INTERFAZ ----------
    def build_ui(self):
        # Barra superior
        top_frame = tk.Frame(self.root, bg="#FFD1DC")
        top_frame.pack(fill="x", padx=10, pady=5)
        tk.Button(top_frame, textvariable=self.var_lang_btn, command=self.change_language,
                  bg="#FF69B4", fg="white", font=("Arial", 10, "bold"),
                  bd=0, cursor="hand2").pack(side="right")

        # Encabezado
        tk.Label(self.root, textvariable=self.var_app_title, bg="#FFD1DC",
                 fg="#4B0082", font=("Comic Sans MS", 22, "bold")).pack(pady=(5, 0))
        tk.Label(self.root, textvariable=self.var_app_subtitle, bg="#FFD1DC",
                 fg="#8A2BE2", font=("Comic Sans MS", 12)).pack(pady=(0, 10))

        # Pestañas
        tab_frame = tk.Frame(self.root, bg="#FFD1DC")
        tab_frame.pack(pady=5)
        
        self.btn_tab_kids = tk.Button(tab_frame, textvariable=self.var_tab_kids,
                                       command=lambda: self.switch_view("kids"),
                                       bg="#FF69B4", fg="white", font=("Arial", 12, "bold"),
                                       bd=0, padx=20, pady=8, cursor="hand2")
        self.btn_tab_kids.pack(side="left", padx=5)
        
        self.btn_tab_real = tk.Button(tab_frame, textvariable=self.var_tab_real,
                                       command=lambda: self.switch_view("real"),
                                       bg="#9370DB", fg="white", font=("Arial", 12, "bold"),
                                       bd=0, padx=20, pady=8, cursor="hand2")
        self.btn_tab_real.pack(side="left", padx=5)

        # Contenedor de vistas
        self.view_container = tk.Frame(self.root, bg="#FFD1DC")
        self.view_container.pack(fill="both", expand=True)

        # --- VISTA KIDS ---
        self.kids_view = tk.Frame(self.view_container, bg="#FFD1DC")
        self.mascot_label = tk.Label(self.kids_view, text="🤖", bg="#FFD1DC", font=("Arial", 55))
        self.mascot_label.pack(pady=5)
        
        tk.Label(self.kids_view, textvariable=self.var_status, bg="#FFD1DC",
                 fg="#333333", font=("Arial", 14, "bold"), wraplength=650).pack(pady=5)
        tk.Label(self.kids_view, textvariable=self.var_progress, bg="#FFD1DC",
                 fg="#333333", font=("Arial", 11)).pack()
        self.progress_bar = ttk.Progressbar(self.kids_view, orient="horizontal",
                                             length=450, mode="determinate")
        self.progress_bar.pack(pady=5)
        self.btn_scan = tk.Button(self.kids_view, textvariable=self.var_btn_scan,
                                   command=self.start_kids_scan, bg="#32CD32", fg="white",
                                   font=("Arial", 16, "bold"), bd=0, padx=30, pady=10,
                                   cursor="hand2", activebackground="#228B22")
        self.btn_scan.pack(pady=10)

        # --- VISTA REAL ---
        self.real_view = tk.Frame(self.view_container, bg="#FFD1DC")
        tk.Label(self.real_view, text="🔬", bg="#FFD1DC", font=("Arial", 45)).pack(pady=5)
        tk.Label(self.real_view, textvariable=self.var_status, bg="#FFD1DC",
                 fg="#333333", font=("Arial", 12, "bold"), wraplength=700).pack(pady=5)
        tk.Label(self.real_view, textvariable=self.var_progress, bg="#FFD1DC",
                 fg="#333333", font=("Arial", 11)).pack()
        self.progress_bar_real = ttk.Progressbar(self.real_view, orient="horizontal",
                                                  length=450, mode="determinate")
        self.progress_bar_real.pack(pady=5)

        # Botón escanear real
        self.btn_real_scan = tk.Button(self.real_view, textvariable=self.var_btn_real_scan,
                                        command=self.confirm_real_scan, bg="#9370DB", fg="white",
                                        font=("Arial", 14, "bold"), bd=0, padx=20, pady=10,
                                        cursor="hand2", activebackground="#7B68EE")
        self.btn_real_scan.pack(pady=8)

        # Fila de botones de cuarentena
        quarantine_btn_frame = tk.Frame(self.real_view, bg="#FFD1DC")
        quarantine_btn_frame.pack(pady=5)

        self.btn_quarantine = tk.Button(quarantine_btn_frame, textvariable=self.var_btn_quarantine,
                                         command=self.do_quarantine, bg="#FF6347", fg="white",
                                         font=("Arial", 11, "bold"), bd=0, padx=15, pady=8,
                                         cursor="hand2", activebackground="#DC143C")
        self.btn_quarantine.pack(side="left", padx=5)

        self.btn_restore = tk.Button(quarantine_btn_frame, textvariable=self.var_btn_restore,
                                      command=self.do_restore, bg="#3CB371", fg="white",
                                      font=("Arial", 11, "bold"), bd=0, padx=15, pady=8,
                                      cursor="hand2", activebackground="#2E8B57")
        self.btn_restore.pack(side="left", padx=5)

        # Etiqueta con la ubicación de cuarentena
        tk.Label(self.real_view, text=f"{self.texts[self.lang]['quarantine_folder']} {QUARANTINE_DIR}",
                 bg="#FFD1DC", fg="#666", font=("Arial", 8, "italic")).pack(pady=(5, 0))

        # --- ÁREA DE TEXTO COMPARTIDA ---
        self.history_label = tk.Label(self.root, textvariable=self.var_history,
                                       bg="#FFD1DC", fg="#4B0082",
                                       font=("Arial", 11, "bold"))
        self.history_label.pack(anchor="w", padx=50, pady=(5, 0))

        self.history_text = tk.Text(self.root, height=9, width=80, bg="white",
                                     fg="#333333", font=("Consolas", 9),
                                     bd=2, relief="solid", wrap="word")
        self.history_text.pack(pady=5, padx=50)
        self.history_text.config(state="disabled")
        self.refresh_history_view()

    # ---------- CAMBIO DE VISTA ----------
    def switch_view(self, view):
        self.current_view = view
        if view == "kids":
            self.real_view.pack_forget()
            self.kids_view.pack(fill="both", expand=True)
            self.btn_tab_kids.config(bg="#FF69B4")
            self.btn_tab_real.config(bg="#9370DB")
            self.var_status.set(self.texts[self.lang]["status_ready"])
            self.var_history.set(self.texts[self.lang]["history_kids"])
        else:
            self.kids_view.pack_forget()
            self.real_view.pack(fill="both", expand=True)
            self.btn_tab_kids.config(bg="#CCCCCC")
            self.btn_tab_real.config(bg="#5D3FD3")
            self.var_status.set(self.texts[self.lang]["status_real_ready"])
            self.var_history.set(self.texts[self.lang]["history_real"])
        self.refresh_history_view()

    def refresh_history_view(self):
        self.history_text.config(state="normal")
        self.history_text.delete(1.0, "end")
        if self.current_view == "kids":
            if self.lang == "es":
                self.history_text.insert("end", "   Historial de amenazas atrapadas:\n   - Ninguna todavía. ¡Sigue así!\n")
            else:
                self.history_text.insert("end", "   Caught threat history:\n   - None yet. Keep it up!\n")
        else:
            if self.lang == "es":
                self.history_text.insert("end", "   El reporte del análisis real aparecerá aquí.\n")
            else:
                self.history_text.insert("end", "   The real scan report will appear here.\n")
        self.history_text.config(state="disabled")

    # =========================================================
    # ============== MODO KIDS (SIMULADO) =====================
    # =========================================================
    def start_kids_scan(self):
        if self.is_scanning: return
        self.is_scanning = True
        self.btn_scan.config(state="disabled", bg="#A9A9A9")
        self.progress_bar["value"] = 0
        self.refresh_history_view()
        threading.Thread(target=self.run_kids_scan, daemon=True).start()

    def run_kids_scan(self):
        t = self.texts[self.lang]
        self.var_status.set(t["status_scanning"])
        
        pasos = ["Revisando la carpeta de Descargas...", "Buscando en el Escritorio...",
                 "Analizando la memoria RAM...", "Revisando los archivos del sistema...",
                 "Limpiando la papelera...", "Buscando virus escondidos..."]
        if self.lang == "en":
            pasos = ["Checking Downloads folder...", "Searching the Desktop...",
                     "Analyzing RAM memory...", "Checking system files...",
                     "Cleaning recycle bin...", "Looking for hidden viruses..."]

        total = len(pasos)
        for i, paso in enumerate(pasos):
            self.var_status.set(f"🔍 {paso}")
            time.sleep(0.7)
            self.progress_bar["value"] = ((i + 1) / total) * 100
            self.root.update_idletasks()

        time.sleep(0.4)
        if random.choice([True, False]):
            self.var_status.set(t["status_clean"])
            self.mascot_label.config(text="😊")
            result = "✅ ¡Sistema limpio! / System clean!"
        else:
            self.var_status.set(t["status_found"])
            self.mascot_label.config(text="😲")
            result = "⚠️ Virus de juguete atrapado / Toy virus caught!"

        self.history_text.config(state="normal")
        self.history_text.insert("end", f"   - {time.strftime('%H:%M:%S')} | {result}\n")
        self.history_text.see("end")
        self.history_text.config(state="disabled")

        self.is_scanning = False
        self.btn_scan.config(state="normal", bg="#32CD32")
        self.var_btn_scan.set(self.texts[self.lang]["btn_scan"])

    # =========================================================
    # ============== MODO REAL (ANÁLISIS REAL) ================
    # =========================================================
    def confirm_real_scan(self):
        if self.is_scanning: return
        t = self.texts[self.lang]
        if messagebox.askyesno(t["warning_title"], t["warning_msg"]):
            self.start_real_scan()

    def start_real_scan(self):
        self.is_scanning = True
        self.threats_found = []
        self.suspicious_found = []
        self.btn_real_scan.config(state="disabled", bg="#A9A9A9")
        self.progress_bar_real["value"] = 0
        self.history_text.config(state="normal")
        self.history_text.delete(1.0, "end")
        self.history_text.config(state="disabled")
        threading.Thread(target=self.run_real_scan, daemon=True).start()

    def calculate_hash(self, filepath):
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                buf = f.read(65536)
                while buf:
                    hasher.update(buf)
                    buf = f.read(65536)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError, OSError, IsADirectoryError):
            return None

    def log_real(self, mensaje):
        self.root.after(0, self._append_real_log, mensaje)

    def _append_real_log(self, mensaje):
        self.history_text.config(state="normal")
        self.history_text.insert("end", mensaje + "\n")
        self.history_text.see("end")
        self.history_text.config(state="disabled")

    def run_real_scan(self):
        t = self.texts[self.lang]
        self.var_status.set(t["status_real_scanning"])
        
        if not PSUTIL_AVAILABLE:
            self.log_real(t["real_no_psutil"])

        user_home = os.path.expanduser("~")
        carpetas = [
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Documents"),
        ]
        if platform.system() == "Windows":
            carpeta_temp = os.environ.get("TEMP") or os.path.join(user_home, "AppData", "Local", "Temp")
            carpetas.append(carpeta_temp)
        else:
            carpetas.append("/tmp")

        carpetas = [c for c in carpetas if os.path.exists(c)]

        self.log_real(f"📁 {t['real_folders']}")
        for c in carpetas:
            self.log_real(f"   → {c}")

        # Hash del EICAR (estándar de la industria)
        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        hashes_maliciosos = {eicar_hash: "EICAR-Test-File"}

        extensiones_dobles = (".pdf.exe", ".docx.exe", ".jpg.exe", ".txt.exe",
                              ".xls.exe", ".png.exe", ".mp3.exe", ".mp4.exe")
        nombres_sospechosos = ["keylogger", "mimikatz", "netcat",
                                "trojan", "ransomware", "backdoor"]

        archivos_escaneados = 0

        total_archivos = 0
        for carpeta in carpetas:
            for _, _, files in os.walk(carpeta):
                total_archivos += len(files)
        if total_archivos == 0:
            total_archivos = 1

        for carpeta in carpetas:
            for root_dir, _, files in os.walk(carpeta):
                for file in files:
                    filepath = os.path.join(root_dir, file)
                    archivos_escaneados += 1
                    
                    progreso = min((archivos_escaneados / total_archivos) * 100, 100)
                    self.root.after(0, lambda p=progreso: self.progress_bar_real.config(value=p))
                    self.var_status.set(f"🔍 {file[:50]}...")

                    # 1. Hash conocido (EICAR)
                    file_hash = self.calculate_hash(filepath)
                    if file_hash and file_hash in hashes_maliciosos:
                        nombre = hashes_maliciosos[file_hash]
                        self.threats_found.append({"path": filepath, "reason": nombre})
                        self.log_real(f"   ❗ {t['real_eicar']} {filepath}")

                    # 2. Doble extensión
                    if file.lower().endswith(extensiones_dobles):
                        self.suspicious_found.append({"path": filepath, "reason": "Double extension"})
                        self.log_real(f"   ⚠️ Doble extensión: {filepath}")

                    # 3. Nombre sospechoso
                    nombre_lower = file.lower()
                    for mal_nombre in nombres_sospechosos:
                        if mal_nombre in nombre_lower and file.lower().endswith((".exe", ".bat", ".sh", ".py")):
                            self.suspicious_found.append({"path": filepath, "reason": f"Suspicious name: {mal_nombre}"})
                            self.log_real(f"   ⚠️ Nombre sospechoso: {filepath}")
                            break

        # Análisis de procesos
        procesos_analizados = 0
        procesos_sospechosos = []
        if PSUTIL_AVAILABLE:
            self.log_real(f"\n🔎 {t['real_processes']}")
            try:
                for proc in psutil.process_iter(['name', 'pid']):
                    try:
                        nombre = proc.info['name']
                        if not nombre: continue
                        procesos_analizados += 1
                        nombre_lower = nombre.lower()
                        for mal_nombre in nombres_sospechosos:
                            if mal_nombre in nombre_lower:
                                procesos_sospechosos.append(f"{nombre} (PID: {proc.info['pid']})")
                                self.log_real(f"   {t['real_process_alert']} {nombre} (PID: {proc.info['pid']})")
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except Exception as e:
                self.log_real(f"   Error: {e}")

        # Reporte final
        self.log_real("\n" + "=" * 60)
        self.log_real(f"📊 {t['real_files']} {archivos_escaneados}")
        self.log_real(f"🎯 {t['real_threats']} {len(self.threats_found)}")
        if PSUTIL_AVAILABLE:
            self.log_real(f"⚙️  {t['real_processes']} {procesos_analizados}")

        if not self.threats_found and not self.suspicious_found and not procesos_sospechosos:
            self.log_real(f"\n✅ {t['real_clean']}")
        else:
            if self.threats_found:
                self.log_real(f"\n🛑 {t['real_threats']}")
                for a in self.threats_found:
                    self.log_real(f"   → {a['path']}")
            if self.suspicious_found:
                self.log_real(f"\n{t['real_suspicious']}")
                for s in self.suspicious_found:
                    self.log_real(f"   → {s['path']}")

        if self.threats_found:
            self.log_real(f"\n💡 Hay {len(self.threats_found)} amenaza(s). Puedes moverlas a cuarentena con el botón naranja.")
        self.log_real("=" * 60)

        self.var_status.set(t["status_real_done"])
        self.is_scanning = False
        self.root.after(0, lambda: self.btn_real_scan.config(state="normal", bg="#9370DB"))
        self.root.after(0, lambda: self.progress_bar_real.config(value=100))

    # =========================================================
    # ============== CUARENTENA REAL ==========================
    # =========================================================
    def ask_pin(self):
        """Pide el PIN parental. Devuelve True si es correcto."""
        t = self.texts[self.lang]
        pin = simpledialog.askstring(t["pin_title"], t["pin_msg"], show="*")
        if pin is None:
            return False
        if pin == PARENTAL_PIN:
            return True
        messagebox.showerror(t["pin_title"], t["pin_wrong"])
        return False

    def do_quarantine(self):
        """Mueve las amenazas encontradas a la carpeta de cuarentena."""
        t = self.texts[self.lang]
        if not self.threats_found:
            messagebox.showinfo("David Secure", t["quarantine_none"])
            return

        # 1. Autorización parental con PIN
        if not self.ask_pin():
            return

        # 2. Confirmación
        n = len(self.threats_found)
        if not messagebox.askyesno(t["quarantine_confirm_title"],
                                    t["quarantine_confirm_msg"].format(n=n)):
            return

        # 3. Cargar manifest existente
        manifest = self.load_manifest()

        # 4. Mover archivos
        movidos = 0
        errores = []
        for threat in self.threats_found[:]:  # copia para iterar
            origen = threat["path"]
            if not os.path.exists(origen):
                continue
            try:
                nombre = os.path.basename(origen)
                # Añadir marca de tiempo para evitar colisiones
                nuevo_nombre = f"{int(time.time())}_{nombre}"
                destino = os.path.join(QUARANTINE_DIR, nuevo_nombre)
                shutil.move(origen, destino)
                
                # Guardar en manifest
                manifest.append({
                    "quarantined_name": nuevo_nombre,
                    "original_path": origen,
                    "reason": threat["reason"],
                    "date": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                movidos += 1
                self.log_real(t["quarantine_moved"].format(file=nombre))
                self.threats_found.remove(threat)
            except (PermissionError, OSError, shutil.Error) as e:
                errores.append(f"{origen} ({e})")
                self.log_real(t["quarantine_error"].format(file=origen))

        # 5. Guardar manifest
        self.save_manifest(manifest)

        # 6. Mostrar resultado
        msg = t["quarantine_done"].format(n=movidos)
        if errores:
            msg += "\n\n" + "\n".join(errores)
        messagebox.showinfo("David Secure", msg)

    def do_restore(self):
        """Restaura todos los archivos de la cuarentena."""
        t = self.texts[self.lang]
        manifest = self.load_manifest()
        if not manifest:
            messagebox.showinfo("David Secure", t["restore_none"])
            return

        # Autorización parental
        if not self.ask_pin():
            return

        n = len(manifest)
        if not messagebox.askyesno(t["restore_confirm_title"],
                                    t["restore_confirm_msg"].format(n=n)):
            return

        restaurados = 0
        errores = []
        nuevo_manifest = []

        for entry in manifest:
            origen_cuarentena = os.path.join(QUARANTINE_DIR, entry["quarantined_name"])
            destino_original = entry["original_path"]

            if not os.path.exists(origen_cuarentena):
                continue

            try:
                # Asegurar que la carpeta de destino existe
                carpeta_destino = os.path.dirname(destino_original)
                if carpeta_destino and not os.path.exists(carpeta_destino):
                    os.makedirs(carpeta_destino, exist_ok=True)

                # Si el archivo original ya existe, renombrar
                if os.path.exists(destino_original):
                    base, ext = os.path.splitext(destino_original)
                    destino_original = f"{base}_restored_{int(time.time())}{ext}"

                shutil.move(origen_cuarentena, destino_original)
                restaurados += 1
                self.log_real(f"   ♻️ Restaurado: {destino_original}")
            except (PermissionError, OSError, shutil.Error) as e:
                errores.append(f"{entry['quarantined_name']} ({e})")
                nuevo_manifest.append(entry)  # Mantener en cuarentena si falló

        # Guardar manifest actualizado
        self.save_manifest(nuevo_manifest)

        msg = t["restore_done"].format(n=restaurados)
        if errores:
            msg += "\n\n" + "\n".join(errores)
        messagebox.showinfo("David Secure", msg)

    def load_manifest(self):
        if os.path.exists(MANIFEST_FILE):
            try:
                with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def save_manifest(self, manifest):
        try:
            with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, ensure_ascii=False)
        except OSError:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    app = DavidSecureKidsApp(root)
    root.mainloop()
