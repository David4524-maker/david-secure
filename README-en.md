# David Secure

Desktop antivirus engine built in Python (Tkinter)** — hash-based scanning, double-extension heuristics, actual quarantine, and real-time protection against suspicious processes.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Plataforma-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/Estado-Proyecto%20educativo-orange)

> ⚠️ **Important notice:** David Secure is an educational/portfolio project. It **does not replace** a commercial antivirus solution, nor does it offer any detection guarantees. Use it at your own risk and always keep your actual antivirus up to date.

---

> **Notice**: David Secure is a small antivirus tool; it does not aim to serve as the primary shield.

---

## Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Graphical Mode (GUI)](#graphical-mode-gui)
  - [Console Mode (CLI)](#console-mode-cli)
- [Configuration](#-configuration)
- [Project Structure](#-project-structure)
- [How Detection Works](#-how-detection-works)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## Features

- 🔍 **Hash-based scanning (MD5 + SHA-256)** against a local signature database, using a single read pass per file.
- 🧠 **Double-extension heuristics** (`photo.jpg.exe`, `invoice.pdf.exe`, etc.).
- 📂 **Three scanning modes:** quick (Downloads/Desktop/Temp), full (entire user profile), and custom (user-selected folder).
- 🧯 **True quarantine** with persistent metadata: restore, permanently delete, or fully empty.
- 👁️ **Real-time protection** monitoring suspicious background processes (requires `psutil`).
- ⛔ **Configurable exclusions** (in addition to system folders excluded by default: `.git`, `node_modules`, `$RECYCLE.BIN`, etc.).
- ⏹️ **Cancellable** scanning at any time, with a progress bar.
- 🌗 **Light / Dark theme.**
- 📝 Event logging with **log rotation**, report export, and clipboard copying.
- 📥 **Import additional signatures** from a custom JSON file.
- 💻 **Headless CLI mode** to automate scans without opening the interface:
  ```bash
  python david_secure.py --scan quick
  ```
- Persistent configuration across sessions (theme, exclusions, scan history, last result).

## Screenshots

<img width="1099" height="646" alt="Captura de pantalla 2026-09-20 135440" src="https://github.com/user-attachments/assets/af113eb2-fa06-4e2d-94c5-e9e72f6cdd4b" />
<img width="1098" height="639" alt="Captura de pantalla 2026-09-20 135531" src="https://github.com/user-attachments/assets/333217d2-7c20-405e-93cc-334d5e187074" />
<img width="1109" height="656" alt="Captura de pantalla 2026-09-20 135522" src="https://github.com/user-attachments/assets/d61c4cd0-d5a4-4e81-abf9-1aca20416041" />

## Requirements

- Python 3.8 or higher
- `tkinter` (included in most Python installations; on Linux, it may require `sudo apt install python3-tk`)
- `psutil` (optional, enables real-time protection):
  ```bash
  pip install psutil
  ```

  ##  Facility

```bash
git clone https://github.com/tu-usuario/david-secure.git
cd david-secure
pip install -r requirements.txt # or simply: pip install psutil
python david_secure.py
```

## Usage

### Graphical Mode (GUI)

```bash
python david_secure.py
```

From the sidebar, you can navigate between **Info**, **Security** (scans), **Accounts**, **Device**, **Issues** (quarantine), and **Settings**.

Keyboard shortcuts:

| Shortcut | Action |
|---|---|
| `F5` | Start quick scan |
| `Ctrl + Q` | Close the application |

### Console Mode (CLI)

Useful for automating scans (e.g., using `cron` or Task Scheduler):

```bash
# Quick scan
python david_secure.py --scan rapido

# Full scan of a custom path
python david_secure.py --scan completo --path "/ruta/a/analizar"
```

## Configuration

David Secure stores its data in your user folder so that it does not depend on where you run the script:

| File | Content |
|---|---|
| `~/.david_secure/config.json` | Theme, exclusions, maximum file size, scan history |
| `~/.david_secure/signatures.json` | Active signature (hash) database |
| `~/.david_secure/quarantine_meta.json` | Metadata for quarantined files |
| `~/.david_secure/logs/` | Application rotation logs |
| `~/DavidSecure_Quarantine/` | Files moved to quarantine |

**Format for importing custom signatures** (Configuration → *Import signatures*):

```json
[
  { "hash": "44d88612fea8a8f36de82e1278abb02f", "algo": "md5", "name": "Ejemplo.Malware.1" }
]
```

## How detection works

1. **By hash:** MD5 and SHA-256 hashes are calculated for each file (subject to a configurable size limit) and compared against the signature database.
2. **Heuristics:** Files with suspicious double extensions (e.g., `.jpg.exe`) are flagged.
3. Any match is moved to **quarantine** and logged, allowing for later restoration or deletion.

> The default signatures are for **testing purposes** (including the standard hash for the EICAR test file, used industry-wide to verify antivirus functionality without using an actual virus). It is not a database of real malware.

## Roadmap

- [ ] Package as an executable (PyInstaller) for Windows/macOS
- [ ] Signature updates from a verified remote feed
- [ ] Real-time file system monitoring (beyond just processes)
- [ ] Automated tests (pytest)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss the proposed modifications.

1. Fork the project
2. Create your branch (`git checkout -b feature/new-function`)
3. Commit your changes (`git commit -m 'Add new function'`)
4. Push to the branch (`git push origin feature/new-function`)
5. Open a Pull Request

---

## To prevent antivirus software from flagging David Secure as a HackTool:

## On Windows:

- Go to Microsoft Defender.

- Look for "Virus & threat protection."

- Under "Virus & threat protection settings," click "Manage settings"; if the UAC prompt appears, click "Yes."

- Scroll down to "Exclusions" and click "Add or remove exclusions."

- Select "Add an exclusion" and choose the David Secure .py file.

## On macOS

-Open the Terminal

-Paste this in the Terminal
```bash
chmod +x /root/a/you/david_secure.py
```

## If you use third-party antivirus software (e.g., MacKeeper, Norton, Avast)

-Open your antivirus application on your Mac.

-Look for the Settings or Preferences panel.

-Select the Exclusions, Whitelist, or Allowed Items tab.

-Click the add button (+) and select the file david_secure.py so that the scanner does not analyze it.

<p align="center">Made with 🛡️ and Python — an educational project, not a commercial product.</p>
