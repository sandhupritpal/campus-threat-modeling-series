@echo off
setlocal enabledelayedexpansion
title Upload Campus Threat Modeling Series to GitHub
color 0A

echo ======================================================
echo   Campus Threat Modeling Workshop Series Uploader
echo ======================================================
echo.

set "PATH=C:\Program Files\Git\cmd;%PATH%"

echo Checking Git installation...
git --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Git was not found in C:\Program Files\Git\cmd.
    echo Please make sure Git is installed.
    pause
    exit /b 1
)

echo.
echo Step 1: Open GitHub in your browser and create a new repository:
echo   Repository Name: campus-threat-modeling-series
echo   Visibility: Public
echo   Leave all checkboxes UNCHECKED (no README, no license, no gitignore)
echo.
set /p GH_USER="Please enter your GitHub Username (e.g. sandhupritpal): "

if "%GH_USER%"=="" (
    echo [ERROR] Username cannot be blank!
    pause
    exit /b 1
)

echo.
echo Initializing Git repository and committing files...
git init >nul 2>&1
git branch -M main >nul 2>&1
git config user.name "Pritpal Sandhu" >nul 2>&1
git config user.email "pritpal@users.noreply.github.com" >nul 2>&1
git add .
git commit -m "feat: complete campus threat modeling workshop series and STRIDE/DREAD toolkit" >nul 2>&1

echo.
echo Setting up GitHub remote...
git remote remove origin >nul 2>&1
git remote add origin https://github.com/%GH_USER%/campus-threat-modeling-series.git

echo.
echo Uploading project to https://github.com/%GH_USER%/campus-threat-modeling-series.git ...
echo.
echo (A browser popup may appear asking you to Sign In to GitHub. Just click "Sign in with your browser")
echo.

git push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo ======================================================
    echo   SUCCESS! Your project is now live on GitHub!
    echo   View it at: https://github.com/%GH_USER%/campus-threat-modeling-series
    echo ======================================================
) else (
    echo.
    echo [!] If you got an error, please verify that:
    echo     1. Your username is spelled correctly.
    echo     2. The repository 'campus-threat-modeling-series' exists on GitHub.
)

echo.
pause
