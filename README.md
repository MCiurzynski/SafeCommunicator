# Safe Communicator

A secure web-based instant messaging project implementing Zero-Knowledge architecture and full End-to-End Encryption (E2EE). The system is designed so that the intermediary server (backend) never has access to message content, attachments, or user private keys in plain text.

## Key Features

### Security and Cryptography
* **E2EE Encryption:** The entire encryption and decryption process takes place on the client side (in the browser) using the Web Crypto API.
* **Zero-Access Architecture:** The database stores only encrypted data blocks (blobs). User passwords are hashed using the Argon2 algorithm and are unknown to the server in a form that would allow decryption of private keys.
* **Algorithms:**
    * Symmetric encryption: AES-GCM (256-bit).
    * Key exchange: X25519 (ECDH).
    * Digital signatures: Ed25519 (ensuring integrity and sender non-repudiation).
    * Hash function: SHA-256.
* **2FA Authentication:** Support for Time-based One-Time Passwords (TOTP), compatible with Google Authenticator/Authy. TOTP secrets are stored encrypted in the database.

### Utility Functions
* Registration and login (with password strength and entropy validation).
* Sending encrypted messages to other users.
* Support for encrypted attachments (up to 100MB).
* Inbox and Sent folders.
* Password change capability (re-encrypting keys) and password reset (generating new keys).

### Infrastructure Security
* **Rate Limiting:** Protection against Brute-Force attacks (at both Nginx and Flask application levels).
* **Honeypot:** Mechanism to detect and block bots during registration.
* **Timing Attack Protection:** Implementation of "Fake Salt" and "Dummy Verify" for non-existent users.
* **Secure Headers:** Enforcement of HTTPS, HSTS, and strict Content-Security-Policy (CSP).

## Technology Stack

* **Frontend:** HTML5, CSS3, Vanilla JavaScript (ES6 Modules), Web Crypto API.
* **Backend:** Python 3.13, Flask, SQLAlchemy, Flask-Login, Flask-Limiter.
* **Database:** PostgreSQL 18.1 (Alpine).
* **Cache / Sessions:** Redis (Alpine).
* **Web Server / Proxy:** Nginx (Alpine).
* **Containerization:** Docker & Docker Compose.

## Setup Instructions

### 1. Prerequisites
Ensure you have the following installed:
* Docker
* Docker Compose

### 2. Environment Configuration
Create a `.env` file in the main project directory and paste the content below.
**Important:** Change passwords and keys to your own secure values.

```ini
# Database Configuration
POSTGRES_USER=secure_user
POSTGRES_PASSWORD=change_me_to_strong_password
POSTGRES_DB=securechat_db
DB_HOST=db

# Redis Configuration
REDIS_URI=redis://:redis_pass@redis:6379/0
REDIS_PASSWORD=redis_pass

# Application Configuration
# Flask Secret (random string)
SECRET_KEY=very_long_and_random_string_for_sessions

# Encryption key for TOTP secrets in DB (must be HEX, 32 bytes = 64 characters)
# You can generate this in Python: secrets.token_hex(32)
TOTP_ENCRYPTION_KEY=000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f