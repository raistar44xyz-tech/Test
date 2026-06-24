# Netflix Cookie Checker Bot

A professional Telegram bot that validates Netflix session cookies live against Netflix servers, extracts full account details, generates one-click NFToken login links, and handles bulk checking with ZIP export.

## Features

- **Universal format support** — Netscape `.txt`, CookieCheckerPro, pipe-combo, JSON, ZIP bundles
- **Live validation** via Chrome 124 TLS fingerprinting (`curl_cffi`)
- **Full account details** — email, plan, quality, billing date, payment card, profiles
- **NFToken login links** — one-click PC & phone login buttons
- **Bulk checking** — 16x parallel workers, live progress bar, ZIP export of hits
- **Proxy support** — rotating proxy pool with auto health-check and failure tracking
- **Admin dashboard** — real-time Flask status page on port 5000
- **MongoDB support** — optional persistence for hits (activated via `MONGODB_URL`)
- **Beta: Password Changer** — change Netflix account passwords via bot

## Supported Cookie Formats

| Format | Example |
|--------|---------|
| Netscape `.txt` | `.netflix.com TRUE / TRUE … NetflixId ct%3D…` |
| CookieCheckerPro | `[user]-[IN]-[Premium]-[4K+HDR]-[21 Apr 2026]-[VISA]` |
| Pipe-combo | `email:pass \| Country=IN \| NetflixId=ct%3D…` |
| JSON array | `[{"name":"NetflixId","value":"ct%3D…"}]` |
| ZIP bundle | Each `.txt` / `.json` file inside = one account |

## Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message |
| `/help` | Format guide & usage tips |
| `/mode` | Toggle Full / Basic output mode |
| `/settings` | Output format & delivery preferences |
| `/cancel` | Cancel a running bulk check |
| `/setadmin` | Claim admin (first user only) |
| Send file or paste | Auto-detects format and checks |

## Setup with Docker

```bash
docker build -t netflix-checker-bot .

docker run -d \
  -e TELEGRAM_BOT_TOKEN=your_bot_token \
  -e MONGODB_URL=mongodb+srv://user:pass@cluster.mongodb.net/netflix_checker \
  -e ADMIN_ID=your_telegram_id \
  -p 5000:5000 \
  netflix-checker-bot
```

## Setup without Docker

```bash
pip install -r requirements.txt pymongo
export TELEGRAM_BOT_TOKEN=your_bot_token
python bot.py
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | ✅ Yes | From [@BotFather](https://t.me/BotFather) |
| `ADMIN_ID` | Recommended | Your Telegram user ID — grants admin commands |
| `MONGODB_URL` | Optional | MongoDB connection string — saves hits to database |
| `PROXY_LIST` | Optional | Comma-separated proxy list for IP rotation |

## File Structure

| File | Purpose |
|------|---------|
| `bot.py` | Telegram handlers, formatters, bulk processing, ZIP export |
| `checker.py` | Cookie parsing, Netflix HTTP validation, NFToken generation |
| `dashboard.py` | Flask real-time status dashboard |
| `proxy_manager.py` | Rotating proxy pool — add/remove proxies via bot commands |
| `mongodb_store.py` | Optional MongoDB persistence for hits |
| `password_changer.py` | Beta Netflix password changer |
| `stats.py` | Thread-safe in-memory stats tracker |
| `requirements.txt` | Python dependencies |
| `Dockerfile` | Docker build file |
