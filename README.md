#  David Secure 
 
**Motor de antivirus de escritorio construido en Python (Tkinter)** — escaneo por hash, heurística de doble extensión, cuarentena real y protección en tiempo real de procesos sospechosos.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Plataforma-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/Estado-Proyecto%20educativo-orange)

> ⚠️ **Aviso importante:** David Secure es un proyecto educativo / de portafolio. **No sustituye** a una solución antivirus comercial ni ofrece garantías de detección. Úsalo bajo tu propio riesgo y mantén siempre actualizado tu antivirus real.

---

> **Aviso**: David Secure es una pequeña herramienta de anti-virus, no intenta ser el escudo principal

---

##  Tabla de contenido

- [Características](#-características)
- [Capturas de pantalla](#-capturas-de-pantalla)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
  - [Modo gráfico (GUI)](#modo-gráfico-gui)
  - [Modo por consola (CLI)](#modo-por-consola-cli)
- [Configuración](#-configuración)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Cómo funciona la detección](#-cómo-funciona-la-detección)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

##  Características

- 🔍 **Escaneo por hash (MD5 + SHA-256)** contra una base de firmas local, en una sola lectura por archivo.
- 🧠 **Heurística de doble extensión** (`foto.jpg.exe`, `factura.pdf.exe`, etc.).
- 📂 **Tres modos de escaneo:** rápido (Descargas/Escritorio/Temporales), completo (todo el perfil de usuario) y personalizado (eliges la carpeta).
- 🧯 **Cuarentena real** con metadatos persistentes: restaurar, eliminar permanentemente o vaciar por completo.
- 👁️ **Protección en tiempo real** que vigila procesos sospechosos en segundo plano (requiere `psutil`).
- ⛔ **Exclusiones configurables** (además de carpetas de sistema excluidas por defecto: `.git`, `node_modules`, `$RECYCLE.BIN`, etc.).
- ⏹️ Escaneo **cancelable** en cualquier momento, con barra de progreso.
- 🌗 **Tema claro / oscuro.**
- 📝 Registro de eventos con **rotación de logs**, exportación de reportes y copiado del log al portapapeles.
- 📥 **Importación de firmas** adicionales desde un archivo JSON propio.
- 💻 **Modo headless por CLI** para automatizar escaneos sin abrir la interfaz:
  ```bash
  python david_secure.py --scan rapido
  ```
-  Configuración persistente entre sesiones (tema, exclusiones, historial de escaneos, último resultado).

##  Capturas de pantalla

<img width="1099" height="646" alt="Captura de pantalla 2026-09-20 135440" src="https://github.com/user-attachments/assets/af113eb2-fa06-4e2d-94c5-e9e72f6cdd4b" />
<img width="1098" height="639" alt="Captura de pantalla 2026-09-20 135531" src="https://github.com/user-attachments/assets/333217d2-7c20-405e-93cc-334d5e187074" />
<img width="1109" height="656" alt="Captura de pantalla 2026-09-20 135522" src="https://github.com/user-attachments/assets/d61c4cd0-d5a4-4e81-abf9-1aca20416041" />

##  Requisitos

- Python 3.8 o superior
- `tkinter` (incluido en la mayoría de las instalaciones de Python; en Linux puede requerir `sudo apt install python3-tk`)
- `psutil` (opcional, habilita la protección en tiempo real):
  ```bash
  pip install psutil
  ```

##  Instalación

```bash
git clone https://github.com/tu-usuario/david-secure.git
cd david-secure
pip install -r requirements.txt   # o simplemente: pip install psutil
python david_secure.py
```

##  Uso

### Modo gráfico (GUI)

```bash
python david_secure.py
```

Desde la barra lateral puedes navegar entre **Info**, **Seguridad** (escaneos), **Cuentas**, **Dispositivo**, **Problemas** (cuarentena) y **Configuración**.

Atajos de teclado:

| Atajo | Acción |
|---|---|
| `F5` | Iniciar escaneo rápido |
| `Ctrl + Q` | Cerrar la aplicación |

### Modo por consola (CLI)

Útil para automatizar escaneos (por ejemplo, con `cron` o el Programador de tareas):

```bash
# Escaneo rápido
python david_secure.py --scan rapido

# Escaneo completo de una ruta personalizada
python david_secure.py --scan completo --path "/ruta/a/analizar"
```

##  Configuración

David Secure guarda sus datos en la carpeta de tu usuario, para no depender de dónde ejecutes el script:

| Archivo | Contenido |
|---|---|
| `~/.david_secure/config.json` | Tema, exclusiones, tamaño máximo de archivo, historial de escaneos |
| `~/.david_secure/signatures.json` | Base de firmas (hashes) activa |
| `~/.david_secure/quarantine_meta.json` | Metadatos de los archivos en cuarentena |
| `~/.david_secure/logs/` | Logs rotativos de la aplicación |
| `~/DavidSecure_Quarantine/` | Archivos movidos a cuarentena |

**Formato para importar firmas propias** (Configuración → *Importar firmas*):

```json
[
  { "hash": "44d88612fea8a8f36de82e1278abb02f", "algo": "md5", "name": "Ejemplo.Malware.1" }
]
```

##  Cómo funciona la detección

1. **Por hash:** se calcula MD5 y SHA-256 de cada archivo (con límite de tamaño configurable) y se compara contra la base de firmas.
2. **Heurística:** se marcan archivos con doble extensión sospechosa (ej. `.jpg.exe`).
3. Cualquier coincidencia se mueve a **cuarentena** y queda registrada para poder restaurarla o eliminarla después.

> Las firmas incluidas por defecto son de **prueba** (incluye el hash estándar del archivo de prueba EICAR, usado en la industria para verificar que un antivirus funciona sin usar un virus real). No es una base de datos de malware real.

##  Roadmap

- [ ] Empaquetar como ejecutable (PyInstaller) para Windows/macOS
- [ ] Actualización de firmas desde un feed remoto verificado
- [ ] Monitoreo de sistema de archivos en tiempo real (no solo procesos)
- [ ] Tests automatizados (pytest)

##  Contribuir

Los *pull requests* son bienvenidos. Para cambios grandes, abre primero un *issue* para discutir qué te gustaría modificar.

1. Haz un fork del proyecto
2. Crea tu rama (`git checkout -b feature/nueva-funcion`)
3. Haz commit de tus cambios (`git commit -m 'Agrega nueva función'`)
4. Haz push a la rama (`git push origin feature/nueva-funcion`)
5. Abre un Pull Request

---

## Para que antivirus no reconozcan a David Secure como HackTool:

En Windows

-Ve a Microsoft Defender

-Busca "Proteccion cntra virus y amenazas"

-En "Configuracion de proteccion contra virus y amenazas" haz click en "Administrar la configuracion", si te sale UAC dale a "Si"

-Baja hasta "Exclusiones" y haz click en "Añadir o quitar exclusiones"

-Selecciona "Añadir Exclusion" y selecciona el archivo PY de David Secure

## En macOS

-Abre la Terminal

-Pega esto en la Terminal
```bash
chmod +x /ruta/a/tu/david_secure.py
```

## Si usas antivirus de terceros (Ej: MacKeeper, Norton, Avast)

-Abre la aplicación de tu antivirus en la Mac.

-Busca el panel de Configuración o Preferencias.

-Selecciona la pestaña de Exclusiones, Lista blanca (Whitelist) o Elementos permitidos.

-Haz clic en el botón de añadir (+) y selecciona el archivo david_secure.py para que el escáner no lo analice.

<p align="center">Hecho con 🛡️ y Python — un proyecto educativo, no un producto comercial.</p>
