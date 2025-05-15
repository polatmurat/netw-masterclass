@echo off
echo 🟢 Launcher başlatılıyor...

REM Scriptin bulunduğu klasöre geç
cd /d %~dp0

REM Python kontrolü
where python >nul 2>&1
if errorlevel 1 (
    echo 🚫 Python yüklü değil. Lütfen yükleyin.
    pause
    exit /b
)

REM Gerekli modüller
echo 📦 Bağımlılıklar yükleniyor (websockets, requests, beautifulsoup4)...
pip install websockets requests beautifulsoup4 >nul

REM Uygulamayı başlat
python launcher.py
