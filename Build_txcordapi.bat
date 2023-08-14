@echo off
echo Building TXCORDAPI
title TXCORDAPI Builder

pip install -r requirements.txt

pyinstaller txcordapi.py --noconfirm --onefile --console --icon "./favicon.ico"
rmdir /Q /S build
del /Q *.spec
echo Finished Building TXCORDAPI

pause