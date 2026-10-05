@echo off
taskkill /f /im chrome.exe >nul 2>&1
taskkill /f /im cdp_launcher.exe >nul 2>&1
echo CDP killed.
pause
