# Biometric Authentication App

This project provides a simple command-line biometric authentication application. It supports registering users, verifying biometric vectors, and benchmarking verification.

## Prerequisites

- GCC (MSYS2 UCRT64 recommended on Windows)
- OpenSSL library (`-lcrypto`)
- Bash shell for MSYS2 scripts or Windows CMD for batch script

## Files

- `biometric_auth.c` / `biometric_app.c` — Main application source code
- `vec_user1.txt`, `vec_user2.txt` — Example biometric vectors
- `run_windows.bat` — Windows batch script for compilation and testing
- `run_msys2.sh` — Bash script for MSYS2 on Windows
- `biometric_db.json` — Database file (created automatically if missing)

## Usage

### 1. Windows (CMD)

1. Open **Command Prompt** in the project directory.
2. Run the batch script:
   ```cmd
   run_windows.bat
