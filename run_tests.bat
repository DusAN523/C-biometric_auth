@echo off
echo === Test Biometric Auth ===

:: Kompilacia
gcc biometric_auth.c -o biometric_auth -lcrypto
if errorlevel 1 (
    echo [ERROR] Kompilacia zlyhala
    exit /b
)

:: Registracia user1
echo Registrujem user1...
biometric_auth.exe add user1 vec_user1.txt

:: Overenie spravneho vektora
echo Overujem user1 so spravnym vektorom...
biometric_auth.exe verify user1 vec_user1.txt

:: Overenie nespravneho vektora
echo 0.9999,0.8888,0.7777,0.6666,0.5555 > wrong_vec.txt
echo Overujem user1 so ZLYM vektorom...
biometric_auth.exe verify user1 wrong_vec.txt

pause
