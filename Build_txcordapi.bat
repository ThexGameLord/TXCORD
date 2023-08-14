@echo off
echo Building TXCORDAPI
title TXCORDAPI Builder

pyinstaller txcordapi.py --noconfirm --onefile --console --icon "./favicon_io/favicon.ico"
del /Q build
del /Q *.spec
ren dist txcordapi-built
echo Finished Building TXCORDAPI

pause