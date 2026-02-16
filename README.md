# 🔐 QSEC2 — Quantum Secure Encrypted Chat

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

> A real-time, end-to-end encrypted chat prototype featuring **BB84 Quantum Key Distribution (QKD)** simulation and **AES-encrypted messaging** — where the server acts purely as a relay and never sees your plaintext.

---

## ✨ Features

- **🔑 BB84 Quantum Key Exchange** — Clients perform a full BB84 QKD simulation (qubit transmission, basis reconciliation, sifting, and QBER analysis) to establish shared secret keys.
- **🔒 End-to-End Encryption** — All messages are AES-encrypted on the client side. The server relays ciphertext without ever decrypting it.
- **📡 Real-Time Communication** — Built on Flask-SocketIO for instant WebSocket-based messaging and protocol signaling.
- **📊 QBER Analysis** — Live Quantum Bit Error Rate visualization with security threshold monitoring (11% threshold).
- **🎤 Voice Messages** — Record and send encrypted voice messages with real-time waveform visualization.
- **🏠 Room-Based Sessions** — Create or join rooms with unique IDs. Each room has independent key exchange and encryption.
- **🛡️ Zero-Knowledge Server** — The server manages rooms and relays encrypted payloads but never persists or decrypts secret key material.

---

## 🏗️ Architecture

| Layer | Technology | Role |
|---|---|---|
| **Frontend** | HTML5, CSS3, Vanilla JS | UI, WebCrypto, BB84 client logic |
| **Backend** | Python, Flask, Flask-SocketIO | Room management, message relay |
| **Database** | SQLite | Metadata & structured event logs |
| **Encryption** | AES-GCM (client-side) | Message encryption/decryption |
| **Key Exchange** | BB84 QKD Simulation | Quantum-secure key establishment |

### How It Works

```
┌─────────┐     BB84 QKD      ┌─────────┐
│ Client A │◄──────────────────►│ Client B │
│  (Alice) │   Key Exchange    │  (Bob)   │
└────┬─────┘                   └────┬─────┘
     │    AES-Encrypted Msgs        │
     │         ┌─────────┐         │
     └────────►│  Server  │◄───────┘
               │  (Relay) │
               └─────────┘
          Never decrypts content
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- pip

### Local Setup

```bash
# Clone the repository
git clone https://github.com/SinghAbinash/QSEC2.git
cd QSEC2

# Create virtual environment
python -m venv .venv

# Activate (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Activate (macOS/Linux)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python server.py
```

Open **http://localhost:5000** in two browser tabs to test the encrypted chat.

---

## 📁 Project Structure

```
QSEC2/
├── server.py            # Flask + SocketIO app entry point
├── chatcontainer.py     # Socket.IO event handlers (rooms, relay, BB84)
├── db.py                # SQLite database helpers
├── requirements.txt     # Python dependencies
├── render.yaml          # Render deployment config
├── static/
│   ├── client.html      # Landing page — create/join rooms
│   ├── room.html        # Chat room UI
│   ├── room.js          # Client-side logic (BB84, encryption, UI)
│   └── style.css        # Styling
└── data/
    └── qsec2.db         # SQLite database (auto-created)
```

---

## ☁️ Deployment (Render)

This app is configured for one-click deployment on **[Render](https://render.com)**:

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → **New** → **Web Service**
3. Connect your GitHub repo
4. Render auto-detects `render.yaml` and configures everything
5. Your app is live at `https://qsec2.onrender.com`

---

## 🔒 Security Notes

> ⚠️ This is a **prototype** for educational and demonstration purposes.

For production deployment, consider:
- **TLS/HTTPS** — Use HTTPS/WSS for all transport (Render provides this automatically).
- **Ephemeral Key Agreement** — Prefer X25519/ECDH for forward secrecy over long-lived RSA keys.
- **Client-Side Key Storage** — Keep all key material client-side; avoid sending plaintext keys to the server.
- **WebCrypto Audit** — Audit the browser-side crypto flows before relying on them in production.

---

## 👤 Author

**Abinash Singh** — [singhabinash184@gmail.com](mailto:singhabinash184@gmail.com)

---

## 📄 License

This project is for educational and research purposes.