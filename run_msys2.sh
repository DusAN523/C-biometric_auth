#!/usr/bin/env bash
set -euo pipefail

# Always run from the script directory
cd "$(dirname "$0")"

echo "=== Building biometric_app (MSYS2 UCRT64) ==="
gcc -O2 -Wno-deprecated-declarations biometric_app.c -o biometric_app.exe -lcrypto

if [ ! -f biometric_db.json ]; then
  printf '[]\n' > biometric_db.json
  echo "Initialized biometric_db.json"
fi

echo "\n=== Register user1 ==="
./biometric_app.exe add user1 vec_user1.txt MySecretPassword

echo "\n=== Verify user1 (correct vector) ==="
./biometric_app.exe verify user1 vec_user1.txt MySecretPassword

echo "\n=== Verify user1 (wrong vector, expect failure) ==="
set +e
./biometric_app.exe verify user1 vec_user2.txt MySecretPassword
set -e

echo "\n=== Bench verify (5 runs) ==="
./biometric_app.exe bench user1 vec_user1.txt MySecretPassword 5

echo "\nDone."


