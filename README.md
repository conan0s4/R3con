<h1 align="center">R3con</h1>
<p align="center">
  <b>Web Reconnaissance Tool</b><br>
  Passive • Active • Automated Dorking
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-black?style=flat-square">
  <img src="https://img.shields.io/badge/focus-web--pentesting-critical?style=flat-square">
  <img src="https://img.shields.io/badge/type-reconnaissance-blue?style=flat-square">
</p>

---

## Overview

**R3con** is a reconnaissance tool for passive and active recon, built for web penetration testing. It acts as a lightweight framework that combines multiple recon techniques into a single workflow.

---

## Features

- **Passive Recon**
  - Domain enumeration using public data sources (e.g., crt.sh)
  - **Automated Google Dorking**: Deep passive pipeline to identify sensitive leaks.
    - Scans for **Sensitive Files**: `.env`, `.log`, `.conf`, `.sql`, and backups.
    - Detects **Directory Listings**: Exposed "Index of" pages and parent directories.
    - Uncovers **Hidden Portals**: Admin dashboards, login pages, and setup interfaces.
    - Identifies **Information Leaks**: API endpoints and technical documentation.

- **Active Recon**
  - DNS probing via SSL/TLS certificate inspection
  - Banner grabbing for service identification
