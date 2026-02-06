# Nexure Inspector - Chrome Extension

## Overview
Nexure Inspector is a developer tool that analyzes cookies and HTTP headers in real-time to identify security risks such as missing `HttpOnly`/`Secure` flags, weak `SameSite` configuration, long-lived cookies, and exposed session tokens.

## Features
- **Real-time Monitoring**: Inspects `Set-Cookie` headers and cookie changes.
- **Security Analysis**:
  - Missing `HttpOnly` (XSS Risk)
  - Missing `Secure` (Man-in-the-Middle Risk)
  - `SameSite=None` without `Secure`
  - Excessive Expiration Dates (> 30 days)
  - **New**: Session tokens in URL parameters.
- **Scoring System**: Calculates a security score (0-100) for the current site.
- **Remediation Advice**: Provides actionable fixes for developers (e.g., "Set HttpOnly flag").

## Installation
1. Clone or download this repository.
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** (top right toggle).
4. Click **Load unpacked**.
5. Select the folder containing `manifest.json` (the root of this project).

## Usage
1. Open any website you want to audit.
2. Click the extension icon in the toolbar.
3. View the list of detected issues and the security score.
4. Use the "Fix" advice to secure your application.

## Permissions Explained
- `webRequest`, `webRequestBlocking`, `<all_urls>`: Required to inspect HTTP headers (`Set-Cookie`) and URL parameters.
- `cookies`: Required to read cookie attributes (`httpOnly`, `secure`, `sameSite`).
- `storage`: Used to save detected issues locally for the popup to display.

## Architecture
- `manifest.json`: Manifest V3 configuration.
- `background.js`: Service worker that listens to network requests and cookie changes.
- `popup.html/js`: The UI dashboard.
