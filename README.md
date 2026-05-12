<h1 align="center">R3con</h1>
<p align="center">
<b>Web Reconnaissance Tool</b><br>
Passive • Active
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
- Automated Google Dorking: advanced search operators to automate OSINT collection on a target website
- **Active Recon**
- DNS probing via SSL/TLS certificate inspection
- Banner grabbing for service identification


<h2>Usage</h2>

<pre>
python recon.py --target &lt;domain&gt; [-p | -a]
</pre>

<h3>Options</h3>

<table>
  <tr>
    <th>Argument</th>
    <th>Description</th>
    <th>Required</th>
  </tr>
  <tr>
    <td><code>--target</code></td>
    <td>Target domain to perform reconnaissance on</td>
    <td>Yes</td>
  </tr>
  <tr>
    <td><code>-p</code></td>
    <td>Passive reconnaissance mode (runs DNS enumeration only)</td>
    <td>Choose one mode</td>
  </tr>
  <tr>
    <td><code>-a</code></td>
    <td>Active reconnaissance mode (runs DNS probing and banner grabbing)</td>
    <td>Choose one mode</td>
  </tr>
</table>

<h3>Examples</h3>

<pre>
python recon.py --target example.com -p
python recon.py --target example.com -a
</pre>

<ul>
  <li><b>Passive Mode (-p)</b>: Safer and quieter. Performs DNS enumeration only.</li>
  <li><b>Active Mode (-a)</b>: More aggressive. Performs DNS probing and banner grabbing.</li>
</ul>
