# ZeroShare: End-to-End Encrypted File Sharing Platform

ZeroShare is an open-source, client-side encrypted file sharing application. It uses a **Zero-Knowledge Architecture** where files are encrypted directly in the user's browser before transmission to the server. The server never has access to the raw files or decryption keys, guaranteeing total confidentiality.

## Features
- **Client-Side Encryption**: AES-GCM 256-bit encryption occurs locally using the Web Crypto API.
- **Zero-Knowledge Backend**: The server receives only high-entropy, encrypted blobs.
- **Link-Based Decryption**: Key parameters are appended as a URL hash fragment (which is never sent to the server).
- **Auto-Expiry**: Uploaded payloads automatically expire and delete themselves after a set period or single download.

## Cryptographic Design
```
[File] + [Client Generated Key]  == (AES-GCM-256) ==>  [Encrypted Blob]
                                                                |
                                                          (HTTPS Upload)
                                                                v
[Decryption Key in URL Hash] <=========== [Server Stores Encrypted Blob Only]
```

## Tech Stack
- **Frontend**: Vanilla HTML5, Tailwind-inspired Vanilla CSS, JavaScript (Web Crypto API)
- **Backend**: Python, Flask, Flask-CORS
- **Storage**: Ephemeral local disk memory

## Quick Start

### 1. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Server
```bash
python server.py
```
Open `http://localhost:5000` in your web browser.
