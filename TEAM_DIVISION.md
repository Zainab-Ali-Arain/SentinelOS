# SentinelOS — Team Division (who owns which file)

> The code is **not** physically split into member folders — SentinelOS is one
> Python package whose modules import each other, so moving files would break it.
> This file is the ownership map: every file is labelled with the member who
> owns and should present it. Members study their own rows for the viva.

| Member | Area |
|---|---|
| **Member 1 — Zainab Ali Arain** | Monitoring & Detection Engine |
| **Member 2 — Mureed Abbas** | Backend, Database, Agent & Communication |
| **Member 3 — Saifullah** | Frontend Dashboard & Visualization |

---

## Member 1 — Zainab Ali Arain (Monitoring & Detection)
The "sensors + brain": collects telemetry and decides what is suspicious.

| File | What it does |
|---|---|
| `sentinelos/engine.py` | Orchestrator — runs one scan, applies all detectors, raises alerts, triggers recovery |
| `sentinelos/detection.py` | Scoring rules + risk levels (LOW/MEDIUM/HIGH/CRITICAL) |
| `sentinelos/process_monitor.py` | Running-process data (CPU, memory, parent/child, disk writes) |
| `sentinelos/file_monitor.py` | File watching, SHA-256 integrity baseline, versioning, rename/extension detection |
| `sentinelos/network_monitor.py` | Connections → process mapping, suspicious + Tor ports |
| `sentinelos/usb_monitor.py` | Removable drives, what is copied to them, memory change |
| `sentinelos/copyguard.py` | Block protected-file copies to Desktop/Documents/Downloads |
| `sentinelos/recovery.py` | Versioned backups, restore, backup locking, OS lockdown, USB write-protect |
| `sentinelos/lists.py` | IoC blocklist + trusted-program whitelist (hash-based) |
| `sentinelos/system_info.py` | OS / CPU / RAM facts |
| `sentinelos/app_names.py` | Friendly app names / system-process detection |
| `iocs.json` | Indicators of Compromise (blocklist data) |
| `demo/` test scripts | ransomware_test, file_burst_test, darkweb_test, ioc_test, cpu_test, suspicious_test |

## Member 2 — Mureed Abbas (Backend, Database, Agent & Comms)
Serves the API, stores data, authenticates, and handles multi-endpoint communication.

| File | What it does |
|---|---|
| `sentinelos/webapp.py` | Flask app — all page routes, REST API, login/CSRF/roles, agent report endpoint |
| `sentinelos/database.py` | SQLite — events + alerts tables, queries, counts, CSV export, log rotation |
| `sentinelos/remote.py` | Hub (endpoint states), Agent loop, HMAC signing, offline queue |
| `sentinelos/auth.py` | User accounts, salted password hashes, roles, login lockout |
| `sentinelos/setup.py` | First-run admin creation + LAN IP discovery |
| `sentinelos/response.py` | investigate / terminate / quarantine (admin-confirmed) |
| `agent.py` | Agent entry point (runs on a member's laptop) |
| `build_agent.py` | Packages the agent into a zip / exe |
| `main.py` | Command-line entry point (dashboard / agent / CLI / lock / restore) |
| `sentinelos/config.py` | Shared settings (both Member 1 & 2 touch this; Member 2 owns server/comms settings) |

## Member 3 — Saifullah (Frontend Dashboard & Visualization)
Everything the administrator sees.

| File | What it does |
|---|---|
| `sentinelos/templates/base.html` | Layout + navigation (shared by all pages) |
| `sentinelos/templates/overview.html` | Overview page |
| `sentinelos/templates/endpoints.html`, `endpoint.html` | Laptops list / one laptop |
| `sentinelos/templates/alerts.html` | Alerts table + filters |
| `sentinelos/templates/security.html` | Security section (counts + filtered alerts) |
| `sentinelos/templates/activity.html` | Activity log |
| `sentinelos/templates/warroom.html` | 3D War Room page |
| `sentinelos/templates/users.html`, `login.html`, `_icons.html` | Users, login, icons |
| `sentinelos/static/app.js` | Shared JS — API polling, tables, modals, toasts, theme, command palette |
| `sentinelos/static/scene3d.js` | Custom 3D engine (plain canvas, no library) for the War Room |
| `sentinelos/static/style.css` | Full design system (light/dark themes, cards, KPIs, tables) |

---

## Shared / everyone
- `sentinelos/config.py` — settings used across all parts (each member reads the flags for their area).
- `sentinelos/__init__.py` — package marker.
- `tests/` — unit tests (each member can add tests for their own part).
- `README.md`, `requirements.txt` — project docs and dependencies.

> Full detail for each part is in **SentinelOS_Technical_Documentation.docx**
> (Part 1 — member division, and Part 3.4 — feature-by-feature).
