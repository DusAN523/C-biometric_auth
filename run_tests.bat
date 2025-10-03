@echo off
echo === Test Biometric Auth ===

:: Compilation
gcc biometric_auth.c -o biometric_auth -lcrypto
if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b
)

:: Register user1
echo Registering user1...
biometric_auth.exe add user1 vec_user1.txt

:: Verify correct vector
echo Verifying user1 with correct vector...
biometric_auth.exe verify user1 vec_user1.txt

:: Verify incorrect vector
echo 0.9999,0.8888,0.7777,0.6666,0.5555 > wrong_vec.txt
echo Verifying user1 with WRONG vector...
biometric_auth.exe verify user1 wrong_vec.txt

pause
