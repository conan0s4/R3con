<div align="center">

# Surface x Dark Web Scraper

### Web Scraping Tool for OSINT Data Extraction

Passive • Active Scraping

</div>

---

<p align="center">
  <img src="https://img.shields.io/badge/status-active-brightgreen" />
  <img src="https://img.shields.io/badge/type-scraper-blue" />
  <img src="https://img.shields.io/badge/focus-osint-red" />
</p>

---

## Overview

Surface x Dark Web Scraper is a lightweight Python-based scraping tool used for extracting publicly available information from web pages.

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

## Installation

```bash
git clone https://github.com/yourname/scraper.git
cd scraper
pip install -r requirements.txt
