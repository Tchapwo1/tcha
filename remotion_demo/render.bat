@echo off
echo ========================================================
echo   Tcha Protection Pro 30s Video Teaser Headless Renderer
echo   Optimized for Windows Laptop (i5 / 8GB RAM Budget)
echo ========================================================
echo.

if not exist node_modules (
    echo [*] Installing Remotion dependencies...
    call npm install
)

if not exist out (
    mkdir out
)

echo [*] Starting headless render of TchaDemo...
echo [*] Concurrency: 1, Codec: H.264 (yuv420p), Resolution: 1920x1080 @ 30fps
call npx remotion render src/index.ts TchaDemo out/tcha_teaser.mp4 --concurrency=1 --gl=angle --codec=h264 --pixel-format=yuv420p --crf=20

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [OK] Video successfully rendered to out\tcha_teaser.mp4!
) else (
    echo.
    echo [ERROR] Render encountered an issue. Check the logs above.
)
