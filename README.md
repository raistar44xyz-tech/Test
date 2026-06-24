# Netflix Cookie Checker Bot

  A Telegram bot that validates Netflix cookies live against Netflix servers, reports full account details, generates NFToken login links, and handles bulk checking with ZIP export.

  ## Features

  - Universal format support — Netscape .txt, CookieCheckerPro, pipe-combo, JSON, ZIP bundles
  - Live validation via Chrome124 TLS fingerprinting (curl_cffi)
  - Full account details — email, plan, quality, billing, payment card
  - NFToken one-click PC & phone login buttons
  - Bulk checking — 16x parallel, live progress bar, ZIP export of all hits
  - Status dashboard on port 5000

  ## Setup

  ```bash
  pip install -r requirements.txt
  export TELEGRAM_BOT_TOKEN=your_token_here
  python bot.py
  ```

  ## Supported Cookie Formats

  | Format | Example |
  |--------|---------|
  | Netscape .txt | `.netflix.com TRUE / TRUE … NetflixId ct%3D…` |
  | CookieCheckerPro | `[user]-[IN]-[Premium]-…` |
  | Pipe-combo | `email:pass \| Country=IN \| NetflixId=ct%3D…` |
  | JSON array | `[{"name":"NetflixId","value":"ct%3D…"}]` |
  | ZIP bundle | Each file inside = 1 account |

  ## Commands

  | Command | Description |
  |---------|-------------|
  | /start | Welcome message |
  | /help | Format guide |
  | /mode | Toggle Full / Basic output |
  | Send file or paste | Auto-detects and checks |

  ## Environment Variables

  | Variable | Required |
  |----------|----------|
  | TELEGRAM_BOT_TOKEN | Yes — from @BotFather |

  ## Files

  | File | Purpose |
  |------|---------|
  | bot.py | Telegram handlers, formatters, bulk processing, ZIP export |
  | checker.py | Cookie parsing, Netflix HTTP validation, NFToken generation |
  | dashboard.py | Flask status dashboard |
  | stats.py | Thread-safe in-memory stats |
  | requirements.txt | Dependencies |
  