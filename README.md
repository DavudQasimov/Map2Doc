<h1 align="center">
  <img src="logoo.png" width="20%" height="30%" style="vertical-align: middle;">
</h1>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com/?lines=Map2Doc;&font=Fira%20Code&center=true&width=380&height=50&duration=4000&pause=1000" alt="Example Usage - README Typing SVG">
</p>

# Map2Doc

```
   __  __             ____  ____
  |  \/  | __ _ _ __ |___ \|  _ \  ___   ___
  | |\/| |/ _` | '_ \  __) | | | |/ _ \ / __|
  | |  | | (_| | |_) |/ __/| |_| | (_) | (__
  |_|  |_|\__,_| .__/|_____|____/ \___/ \___|
               |_|
```

**A unified SMB/AD enumeration wrapper with automatic reporting.**
*Developed by **Davud Qasimov***

Map2Doc merges the most common SMB reconnaissance tools — **NetExec** (formerly CrackMapExec), **smbclient**, and **smbmap** — into a single command, and automatically generates a clean, timestamped report (`.md` or `.txt`) after every enumeration step. No more juggling three terminals and copy-pasting output by hand.

---

## ✨ Features

- 🔗 **One command, three tools** — runs NetExec, smbclient, and smbmap enumeration in a single pass
- 📝 **Auto-reporting** — every step is appended live to a report file, saved in your current working directory
- 🎛️ **Selective execution** — run only the tools you need with `--only`
- 🧩 **Extra NetExec modules** — pass additional flags like `--pass-pol`, `--sessions`, `--rid-brute=10000` on the fly
- 🕶️ **Null-session friendly** — works out of the box with anonymous/guest access, a common entry point in AD assessments
- 📄 **Two report formats** — clean Markdown (with tables and code blocks) or plain text
- 📏 **Readable output** — long tool output is automatically wrapped so reports never blow past your terminal width

---

## 📦 Requirements

Map2Doc is a lightweight orchestrator — it doesn't reimplement SMB protocol logic. It simply calls tools that are already standard on any pentesting distro:

- Python 3.8+
- [`netexec`](https://github.com/Pennyw0rth/NetExec) (or `crackmapexec`/`cme` as a fallback)
- `smbclient` (Samba client suite)
- `smbmap`

All three come preinstalled on Kali Linux.

---

## 🌍 Making Map2Doc Globally Accessible

To run `mdc` as a system-wide command from any path in your terminal, follow these steps:

### 1. Make the Script Executable

Navigate to your project directory and grant execution permissions to the main script:

```bash
chmod +x mdc.py
```

### 2. Create a Global Symbolic Link

Create a symlink in `/usr/local/bin` so the system recognizes `mdc` as a global command. This ensures that any updates you pull or push in your local repository will instantly apply to the global command:

```bash
sudo ln -s /full/path/to/your/Map2Doc/mdc.py /usr/local/bin/mdc
```

*(Replace `/full/path/to/your/Map2Doc/mdc.py` with the absolute path to your file).*

### 3. Verify the Installation

Open a new terminal window in any random directory (e.g., your home directory) and run:

```bash
mdc -h
```

If the help menu appears successfully, the global configuration is complete. You can now run `mdc <target>` from anywhere, with no need to `cd` into the project folder or type `python3` first.

---

## 🚀 Usage

```bash
mdc <target> [options]
```

### Basic recon (anonymous, all three tools, Markdown report)
```bash
mdc 10.10.10.10
```

### Authenticated scan
```bash
mdc 10.10.10.10 -u admin -p Password123
```

### Null session / guest auth
```bash
mdc 10.10.10.10 -u '' -p ''
```

### Choose report format
```bash
mdc 10.10.10.10 -f txt
mdc 10.10.10.10 -f md
```

### Run only specific tools
```bash
mdc 10.10.10.10 --only netexec
mdc 10.10.10.10 --only netexec smbclient
```

### Extra NetExec modules
```bash
mdc 10.10.10.10 -u admin -p Password123 --modules pass-pol sessions
mdc 10.10.10.10 -u '' -p '' --modules rid-brute=10000
```

### Full combo
```bash
mdc 10.10.10.10 -u admin -p Password123 -f md --only netexec smbmap --modules pass-pol sessions
```

---

## 📋 CLI Reference

| Flag | Description |
|------|-------------|
| `target` | Target IP or hostname (required) |
| `-u`, `--user` | Username (use `''` for null session) |
| `-p`, `--password` | Password (use `''` for null session) |
| `-f`, `--format` | Report format: `md` (default) or `txt` |
| `--only` | Run only the specified tools: `netexec`, `smbclient`, `smbmap` |
| `--modules` | Extra NetExec modules, e.g. `pass-pol`, `sessions`, `rid-brute=10000` |

---

## 📄 Sample Report Output (Markdown)

```markdown
# Map2Doc Report

| Field  | Value |
|--------|-------|
| Target | `10.10.10.10` |
| Date   | 2026-09-21 15:40:32 |

---

## 1. NetExec - Basic Host Information

| | |
|---|---|
| **Tool** | `nxc` |
| **Command** | `nxc smb 10.10.10.10` |
| **Status** | OK |

​```text
SMB   10.10.10.10   445   HOSTNAME   [*] Windows 10 / Server 2019 Build 17763 x64
    (domain:example.local) (signing:True) (SMBv1:None) (Null Auth:True)
​```
```

---

## ⚠️ Disclaimer

Map2Doc is intended strictly for **authorized penetration testing, red team engagements, and CTF/lab environments** (e.g. HackTheBox, TryHackMe). Only use it against systems you own or have explicit written permission to test. The author is not responsible for misuse of this tool.

---

## 👤 Author

**Davud Qasimov** ([@etozryx_13553](https://discord.com))
- Medium: [https://medium.com/@qasimovdavud39](https://medium.com/@qasimovdavud39)
- LinkedIn: [linkedin.com/in/davud-qasimov-798928303](https://linkedin.com/in/davud-qasimov-798928303)

---

## 📜 License

MIT License — free to use, modify, and distribute with attribution.
