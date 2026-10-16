# Raymida Mail System

A self-hosted, fault-tolerant email system with multi-user support, running on a home server/laptop without a dedicated IP or open port 25.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Production_Ready-success)

## 📖 Table of Contents

- [Architecture](#-architecture)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation Guide](#-installation-guide)
  - [1. System Dependencies](#1-system-dependencies)
  - [2. Project Setup](#2-project-setup)
  - [3. Cloudflare DNS Configuration](#3-cloudflare-dns-configuration)
  - [4. Cloudflare Email Routing](#4-cloudflare-email-routing)
  - [5. Cloudflare Worker Setup](#5-cloudflare-worker-setup)
  - [6. Cloudflare Tunnel Setup](#6-cloudflare-tunnel-setup)
  - [7. Cloudflare R2 Bucket (Fallback Queue)](#7-cloudflare-r2-bucket-fallback-queue)
  - [8. Resend Account Setup](#8-resend-account-setup)
  - [9. Credentials Configuration](#9-credentials-configuration)
  - [10. User Creation](#10-user-creation)
  - [11. Systemd Services Installation](#11-systemd-services-installation)
- [Usage](#-usage)
- [Security Notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)
- [License](#-license)

---

## 🏗 Architecture

```
[Sender]
   │ (SMTP)
   ▼
[Cloudflare Email Routing]
   │
   ▼
[Cloudflare Worker] ─(health check)──► [Server Online?]
   │                                         │
   ├─ YES ─────────────────────────────────► [Cloudflare Tunnel]
   │                                             │
   │                                             ▼
   │                                   [inbound_receiver.py : 8925]
   │                                             │ (atomic Maildir write)
   │                                             ▼
   │                                   [~/mail/<user>/new/]
   │                                             │
   │                                             ▼
   │                                   [pochta_api.py : 8926] ◄── [Web UI]
   │                                             │
   │                                             ▼
   └─ NO ───────────────────────────────► [Cloudflare R2 Bucket] (Fallback Queue)
                                                 │
                                                 ▼ (every 5 min)
                                        [r2_sync.py] ──────────
```

**Key Design Decisions:**
- **No port 25 required**: Cloudflare Email Routing receives SMTP and forwards via HTTPS
- **No public IP required**: Cloudflare Tunnel provides secure inbound connectivity
- **Durable fallback**: R2 queues mail when the receiver is unavailable; if both fail, the Worker explicitly rejects the email instead of silently accepting it
- **Maildir format**: Flush files before atomic rename and acknowledgement

---

## ✨ Features

### Core
- **Cloudflare-based email reception** — bypasses ISP port 25 blocks
- **Fault tolerance** — emails queue in R2 when server is down, auto-sync on recovery
- **Multi-user support** — isolated mailboxes with bcrypt password hashing
- **MIME attachments** — drag & drop upload, base64 encoding, full download support
- **Mail search** — search From, To, Subject and a bounded body preview in the selected folder

### Security
- **Built-in Fail2Ban** — in-memory IP banning with whitelist support
- **Real IP detection** — reads `Cf-Connecting-Ip` header through Cloudflare Tunnel
- **XSS protection** — DOMPurify sanitizes all HTML emails
- **Secret isolation** — credentials stored in `~/.r2_credentials` (mode 600), never in Git
- **Expiring sessions** — signed browser cookies bound to the current password and key; password changes revoke previous sessions and API keys

### UI/UX
- **Dark glassmorphism theme** — modern, beautiful interface
- **Smooth animations** — powered by anime.js
- **Unread indicators** — blue accent bar + bold text for new emails
- **Responsive design** — works on desktop and mobile

---

## ⚙️ Prerequisites

### System Requirements
- **OS**: Linux with systemd (tested on Arch/CachyOS, works on Ubuntu/Debian/Fedora)
- **Python**: 3.10 or higher
- **RAM**: 512 MB minimum (system uses ~50 MB at idle)
- **Disk**: 1 GB for system + space for emails

### External Services (all free tier)
- **Cloudflare account** — for DNS, Email Routing, Tunnel, Worker, R2
- **Domain name** — e.g., `raymida.com` (any TLD works)
- **Resend account** — for sending outbound emails (100 emails/day free)

### Network Requirements
- Outbound HTTPS (port 443) — for Cloudflare Tunnel and Resend API
- No inbound ports required — Cloudflare Tunnel handles all inbound traffic

---

## 🚀 Installation Guide

### 1. System Dependencies

**Arch Linux / CachyOS:**
```bash
sudo pacman -S python-bcrypt python-boto3
```

**Ubuntu / Debian:**
```bash
sudo apt install python3-bcrypt python3-boto3
```

**Fedora:**
```bash
sudo dnf install python3-bcrypt python3-boto3
```

**Alternative (pip):**
```bash
pip install bcrypt boto3
```

### 2. Project Setup

Clone or copy the project to your desired location:

```bash
# Option A: Clone from Git (if published)
git clone https://github.com/stone54321/raymidaMail ~/projects/raymida-mail

# Option B: Manual copy (if developing locally)
mkdir -p ~/projects/raymida-mail
cp -r /path/to/your/source/* ~/projects/raymida-mail/

cd ~/projects/raymida-mail
```

Create the mail storage directory:
```bash
mkdir -p ~/mail
```

### 3. Cloudflare DNS Configuration

Go to Cloudflare Dashboard → Your Domain → DNS → Records and add:

| Type | Name | Content | Proxy Status | TTL |
|------|------|---------|--------------|-----|
| MX | @ | route1.mx.cloudflare.net | DNS only | Auto |
| MX | @ | route2.mx.cloudflare.net | DNS only | Auto |
| MX | @ | route3.mx.cloudflare.net | DNS only | Auto |
| TXT | @ | v=spf1 include:resend.com include:_spf.mx.cloudflare.net ~all | DNS only | Auto |
| TXT | _dmarc | v=DMARC1; p=none; rua=mailto:admin@yourdomain.com | DNS only | Auto |
| TXT | resend._domainkey | `v=DKIM1; k=rsa; p=YOUR_RESEND_DKIM_KEY` | DNS only | Auto |

For subdomains (mail, pochta):

| Type | Name | Content | Proxy Status |
|------|------|---------|--------------|
| CNAME | mail | your-tunnel-id.cfargotunnel.com | Proxied |
| CNAME | pochta | your-tunnel-id.cfargotunnel.com | Proxied |

> **Note:** Replace `yourdomain.com` with your actual domain and `your-tunnel-id` with your Cloudflare Tunnel ID (obtained in step 6).

### 4. Cloudflare Email Routing

Go to Cloudflare Dashboard → Email → Email Routing

1. Enable Email Routing for your domain
2. Add a Custom Address:
   - Custom address: `*@yourdomain.com` (catch-all) or specific like `ray@yourdomain.com`
   - Action: Send to a Worker
   - Worker: Select the Worker created in step 5

### 5. Cloudflare Worker Setup

Go to Cloudflare Dashboard → Workers & Pages → Create

1. Name: `mail-router`
2. Paste the source from [`cloudflare/email-worker.mjs`](cloudflare/email-worker.mjs).
   This is the authoritative Worker source; do not reuse the old inline sample.
   If an existing Worker also handles website forms, build the combined Worker in
   the storefront project with this file as its base before deploying. Keep the
   existing bindings and Email Routing rules.

3. **Set Environment Variables & Secrets**:
   - Go to **Worker Settings → Variables and Secrets**
   - Add variable: `PRIYOMNIK` = `https://mail.yourdomain.com/inbound`
   - Add secret/variable: `KEY` = `your_actual_inbound_key` (must match `INBOUND_KEY` / `RAY_MAIL_KEY` in `priyomnik.service`)

4. **Bind R2 Bucket**:
   - Go to **Worker Settings → R2 Bucket Bindings**
   - Click "Add binding"
   - Variable name: `MAIL_QUEUE`
   - R2 bucket: Select `mail-fallback-queue`
   - Click "Save and Deploy"


### 6. Cloudflare Tunnel Setup

Install cloudflared on your server:

```bash
# Arch Linux
sudo pacman -S cloudflared

# Ubuntu/Debian
sudo apt install cloudflared
```

Authenticate:
```bash
cloudflared tunnel login
```

Create tunnel:
```bash
cloudflared tunnel create raymida-mail
```

Configure tunnel (`~/.cloudflared/config.yml`):

```yaml
tunnel: <YOUR_TUNNEL_ID>
credentials-file: /home/tony/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: mail.yourdomain.com
    service: http://localhost:8925
  - hostname: pochta.yourdomain.com
    service: http://localhost:8926
  - service: http_status:404
```

Route DNS:
```bash
cloudflared tunnel route dns raymida-mail mail.yourdomain.com
cloudflared tunnel route dns raymida-mail pochta.yourdomain.com
```

Run as systemd service:
```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

### 7. Cloudflare R2 Bucket (Fallback Queue)

Go to Cloudflare Dashboard → R2 → Create Bucket

1. Name: `mail-fallback-queue`
2. Location: Choose closest to your server

Create API Token:

1. Go to R2 → Manage R2 API Tokens → Create API Token
2. Permissions: Object Read & Write
3. Bucket: `mail-fallback-queue`
4. Copy the credentials (Account ID, Access Key, Secret Key)

### 8. Resend Account Setup

1. Go to [resend.com](https://resend.com) and sign up
2. Add your domain (`yourdomain.com`)
3. Verify domain by adding DNS records (Cloudflare will auto-add if proxied)
4. Go to API Keys → Create API Key
5. Copy the key (starts with `re_`)

### 9. Credentials Configuration

Create the R2 credentials file:

```bash
cp r2_credentials.example ~/.r2_credentials
nano ~/.r2_credentials
```

Fill in your values:
```
R2_ACCOUNT_ID=your_actual_account_id
R2_ACCESS_KEY=your_actual_access_key
R2_SECRET_KEY=your_actual_secret_key
R2_BUCKET_NAME=mail-fallback-queue
```

Set secure permissions:
```bash
chmod 600 ~/.r2_credentials
```

### 10. User Creation

Run the user setup script:

```bash
cd ~/projects/raymida-mail/backend
python3 setup_users.py
```

Follow the prompts:
- Enter username (e.g., ray, tony)
- Enter password (12 characters minimum, 72 UTF-8 bytes maximum)
- Add more users or finish

This creates `~/.raymida_users.json` with bcrypt-hashed passwords.


### 10.5. Frontend Domain Configuration

The web interface has your domain hardcoded. Update it to match your domain:

```bash
nano ~/projects/raymida-mail/frontend/app.js
```

Find this line (around line 375):

```javascript
const MAIL_DOMAIN = 'raymida.com';
```
Replace with your domain:

```javascript
const MAIL_DOMAIN = 'yourdomain.com';
```
> **Note:** This is the only place in the frontend where you need to change the domain. The backend automatically detects it from environment variables.

### 11. Systemd Services Installation

Edit the service templates with your actual values:

```bash
nano ~/projects/raymida-mail/systemd/priyomnik.service
```

Replace `YOUR_INBOUND_KEY_HERE` and `yourdomain.com` (ensure paths match your setup):

```ini
[Unit]
Description=Raymida Mail Inbound Receiver
After=network.target

[Service]
Type=simple
Environment=RAY_MAIL_KEY=your_actual_inbound_key
Environment=MAIL_DOMAIN=yourdomain.com
WorkingDirectory=%h/projects/raymida-mail/backend
ExecStart=/usr/bin/python3 %h/projects/raymida-mail/backend/priyomnik.py 8925
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
```

```bash
nano ~/projects/raymida-mail/systemd/pochta-web.service
```

Replace `YOUR_RESEND_KEY_HERE` and `yourdomain.com`:

```ini
[Unit]
Description=Raymida Mail Web API
After=network.target

[Service]
Type=simple
Environment=RESEND_KEY=re_your_actual_resend_key
Environment=MAIL_DOMAIN=yourdomain.com
WorkingDirectory=%h/projects/raymida-mail/backend
ExecStart=/usr/bin/python3 %h/projects/raymida-mail/backend/pochta_api.py 8926
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
```
> **Note:** WEB_DIR is automatically detected by the Python script relative to its own location, so there is no need to specify it manually in the service file.

Install services:

```bash
mkdir -p ~/.config/systemd/user
cp ~/projects/raymida-mail/systemd/*.service ~/.config/systemd/user/
cp ~/projects/raymida-mail/systemd/*.timer ~/.config/systemd/user/
systemctl --user daemon-reload
```

Enable and start:

```bash
systemctl --user enable --now priyomnik.service
systemctl --user enable --now pochta-web.service
systemctl --user enable --now r2-sync.timer
```

Verify status:

```bash
systemctl --user status priyomnik.service pochta-web.service r2-sync.timer
```

All should show `active (running)` or `active (waiting)` for the timer.

---

## 📧 Usage

### Accessing the Web Interface

Open your browser and navigate to: `https://pochta.yourdomain.com`

1. Enter your username and password (created in step 10)
2. You'll see your mailbox with all emails

### Receiving Email

Send an email to anyname@yourdomain.com
- If server is online: email arrives instantly via Cloudflare Tunnel
- If server is offline: email queues in R2, auto-delivered within 5 minutes of server recovery

### Sending Email

1. Open any email in the interface
2. Write a reply below the message
3. Drag & drop attachments if needed
4. Click "Send"
5. Open **Отправленные** to see accepted replies, recipients and attachments.

Resend is used only for outgoing delivery. A Sent copy means Resend accepted the
message; it is not proof of final delivery to the recipient. Sent history starts
with replies sent after this update; old replies are not reconstructed.

A reply is staged locally before calling Resend. The UI retains one send ID for
an unchanged retry, and the provider request uses an `Idempotency-Key`. Accepted
messages recover into Sent without sending again if the local final move failed.
Uncertain retries older than 23 hours are blocked because Resend's idempotency
window is 24 hours. If an error persists, check provider status before starting a
new reply or reloading and sending again.

### Changing a password

Click **Пароль** in the mailbox toolbar, enter your current password and confirm
the new one. Other browser sessions and the previous Bearer API key stop working;
the current browser receives a new signed session. The CLI `setup_users.py`
performs the same revocation when an administrator resets a password.

Browser sessions expire after 30 days. Existing raw-key cookies are intentionally
invalid after upgrading: sign in once using your existing password. Cookies are
Secure, HttpOnly and SameSite=Lax. `COOKIE_SECURE=false` is only for an isolated
localhost preview; keep the default `true` for the public service.

### Recovery from R2

The sync job routes each object using its `originalTo` envelope metadata, including
BCC mail. Legacy objects without metadata use `To` only when it contains one
unambiguous local recipient. Invalid or ambiguous objects stay in R2 for review.
One failed object does not block later objects; any failure makes the job exit
nonzero. R2 deletion follows a flushed local file and directory entry.

If both the receiver and R2 fail, the Worker calls `setReject`, which gives a
permanent SMTP rejection. The sender may need to send again; automatic retry is
not guaranteed. See [Cloudflare's rejection and error handling documentation](https://developers.cloudflare.com/email-service/api/route-emails/email-handler/).

### Searching

Use the search bar at the top
- Searches across From, Subject, and email body
- Results update in real-time (300ms debounce)

---

## 🔒 Security Notes

- **Never commit secrets**: The `.gitignore` file excludes `.r2_credentials`, `.raymida_users.json`, and `mail/` directory
- **File permissions**: Always use `chmod 600` for credential files
- **API keys**: Use different keys for inbound (Worker) and outbound (Resend)
- **Fail2Ban**: Built-in protection against brute force (5 attempts → 5 min ban)
- **XSS protection**: All HTML emails are sanitized via DOMPurify
- **HTTPS only**: Cloudflare Tunnel provides automatic HTTPS encryption

---

## 🔧 Troubleshooting

### Email not arriving

1. Check Worker logs: Cloudflare Dashboard → Workers → mail-router → Logs
2. Check inbound receiver logs:

   ```bash
   journalctl --user -u priyomnik.service -n 50
   ```

3. Verify DNS MX records are set correctly
4. Check Cloudflare Email Routing is enabled

### Web interface not loading

1. Check API service status:

   ```bash
   systemctl --user status pochta-web.service
   ```

2. Check logs:

   ```bash
   journalctl --user -u pochta-web.service -n 50
   ```

3. Verify Cloudflare Tunnel is running:

   ```bash
   systemctl status cloudflared
   ```

### Emails stuck in R2

1. Check R2 bucket for pending files:

   ```bash
   # Manual sync test
   python3 ~/projects/raymida-mail/backend/r2_sync.py
   ```

2. Check timer status:

   ```bash
   systemctl --user status r2-sync.timer
   ```

### Authentication failures

1. Verify user file exists:

   ```bash
   ls -la ~/.raymida_users.json
   ```

2. Recreate users if needed:

   ```bash
   python3 ~/projects/raymida-mail/backend/setup_users.py
   ```

---

## 📁 Project Structure

```
raymida-mail/
├── backend/
│   ├── priyomnik.py       # Inbound mail receiver (port 8925)
│   ├── pochta_api.py      # Web API with auth & search (port 8926)
│   ├── r2_sync.py         # R2 fallback synchronization
│   └── setup_users.py     # User creation utility
├── frontend/
│   ├── index.html         # Main HTML structure
│   ├── app.js             # Client-side logic
│   ├── style.css          # Dark glassmorphism theme
│   ├── anime.js           # Animation library
│   └── purify.min.js      # Local DOMPurify library
├── tests/
│   ├── test_all_21_items.py # Master regression suite across all 21 items
│   ├── test_tier1_static_cloudflare.py
│   ├── test_tier2_inbound_s3.py
│   ├── test_tier3_user_management.py
│   └── test_tier4_webmail_api_frontend.py
├── systemd/
│   ├── priyomnik.service  # Inbound receiver service template
│   ├── pochta-web.service # Web API service template
│   ├── r2-sync.service    # R2 sync service template
│   └── r2-sync.timer      # Timer (runs every 5 min)
├── r2_credentials.example # Template for R2 credentials
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

---

## Testing

Run without production users, mailboxes or provider credentials:

```bash
python3 -m unittest discover -s tests
node --test tests/email-worker.test.mjs
```

The failure-path suite uses temporary mailboxes and a fake outgoing provider. It
covers recipient metadata, ambiguous queues, password revocation, concurrent
updates, Sent MIME attachments, repeated send IDs and recovery after a local
commit failure. No real messages are sent.

## 📄 License

MIT License - feel free to use, modify, and distribute.

---

## 🤝 Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

---

Built with ❤️ for the self-hosted community
