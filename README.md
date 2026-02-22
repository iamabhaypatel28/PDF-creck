# PDF Password Cracker — Cyber Injection Suite 🥷

Is project mein ek advanced PDF password cracking system hai jo Fast API, PostgreSQL aur John the Ripper (JTR) par based hai. Isme ek futuristic "Hacker" themed UI aur interactive mascot bhi shamil hai.

## 🚀 Features
- **Hacker UI**: Matrix rain animation, neon glow effects aur cursor-following particle network.
- **Interactive Mascot**: "CYBER_SENTINEL" jiski aankhein mouse ko track karti hain.
- **Auto-Delete Logic**: Har user ke liye max 5 PDFs ka limit, nayi file aane par purani file auto-delete ho jayegi.
- **Background Cracking**: John the Ripper backend mein hashes crack karta hai bina system block kiye.
- **Simplified Login**: Email dalo aur seedha dashboard mein enter karo (Passwordless).

---

## 💻 Local Setup Instructions

### 1. Prerequisites
- **Python**: v3.11 ya upar.
- **PostgreSQL**: Local database setup (User: `pdfcreck`, Password: `root`, DB: `pdfcreck`).
- **John the Ripper**: `/home/abhay/Work p/pdf creck/john-bleeding-jumbo/run` folder mein hone chahiye.

### 2. Environment Setup
Virtual environment create karein aur dependencies install karein:
```bash
cd app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the Application
```bash
uvicorn main:app --reload
```
Ab browser mein `http://localhost:8000` kholiye.

---

## 🐳 Docker Setup (Recommended for Live Deployment)

Docker ka use karke aap ise kisi bhi server (Railway, Render, DigitalOcean) par asani se deploy kar sakte hain. Docker image mein John the Ripper aur saari dependencies pre-installed aayengi.

### 1. Build and Run Container
```bash
docker-compose up --build
```

---

## 🌐 Live Deployment (GitHub)

1. Git repository initialize karein:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Hacker PDF Cracker Suite"
   ```
2. GitHub par naya repository banayein aur use link karein.
3. Railway.app par account banayein aur repository ko connect karke "Deploy" karein.

---

**Developed with ❤️ for the Hacker Community**
