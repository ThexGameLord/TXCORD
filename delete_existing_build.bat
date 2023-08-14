@echo off
echo Removing previous build of TXCORDAPI
title TXCORDAPI Build remover

rmdir /Q /S build
rmdir /Q /S dist
echo Finished removing previous build of TXCORDAPI

pause