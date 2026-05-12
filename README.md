<div align="center">

# Scrap3r

### Web Scraping Tool | Data Extraction

</div>

---

<p align="center">
  <img src="https://img.shields.io/badge/status-active-brightgreen" />
  <img src="https://img.shields.io/badge/type-scraper-blue" />
  <img src="https://img.shields.io/badge/focus-osint-red" />
</p>

---

## Overview

Scrap3r is a lightweight Python-based scraping tool used for extracting publicly available information from web pages.

It supports both standard HTTP requests and optional Tor routing for `.onion` domains.

---

## Features

- Web page scraping via HTTP
- Optional Tor routing support
- Extract usernames (`@handles`)
- Extract emails
- Extract IP addresses
- Extract domains and subdomains
- Extract phone numbers
- Extract links (including `.onion`)
- HTML title and heading extraction
- HTML comment extraction
- Regex-based data parsing

---

## Usage

- Target web: URL or domain to target  
- Use Tor: `y` or `n` to enable/disable Tor routing  
- Timeout: request timeout  

### Example

```bash
Target web >> https://example.com/
Use Tor? [y/n] >> y
input timeout >> 10
