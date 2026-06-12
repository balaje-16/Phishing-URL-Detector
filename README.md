# Basic Python URL Phishing Detector

A lightweight, heuristic-based command-line tool written in Python that analyzes URLs for common characteristics associated with phishing attacks.

## How It Works
This tool does not rely on external databases or APIs (like VirusTotal or Google Safe Browsing). Instead, it uses **heuristic analysis** to inspect the structure of the URL itself. It calculates a "Risk Score" based on predefined rules.

### Features Analyzed:
* **IP Addresses:** Checks if an IP is used instead of a domain.
* **'@' Symbols:** Detects if the URL uses an `@` to obscure the true destination.
* **URL Shorteners:** Flags common shortening services (e.g., bit.ly, tinyurl).
* **Length:** Flags excessively long URLs.
* **Subdomains:** Detects excessive dot notation often used to mimic trusted brands.
* **Hyphens:** Flags hyphens in the domain, a common cybersquatting tactic.
* **HTTP Protocol:** Warns if the site does not use an SSL/TLS certificate (HTTPS).

## Prerequisites
* Python 3.x installed on your machine.
* No external libraries are required (uses standard `re` and `urllib` libraries).

## Usage
1. Clone or download the repository.
2. Open a terminal or command prompt.
3. Navigate to the directory containing the script.
4. Run the script:
   ```bash
   python phishing_detector.py
