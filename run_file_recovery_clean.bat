@echo off
chcp 65001 >nul
title DataAnchor - 데이터 복구 도구

echo ========================================
echo   DataAnchor 시작 중...
echo ========================================
echo.

REM 캐시 파일 삭제
echo [1/4] 캐시 파일 정리 중...
del /q __pycache__\*.pyc 2>nul
rmdir /q __pycache__ 2>nul
echo ✓ 캐시 정리 완료
echo.

REM Python 설치 확인
echo [2/4] Python 확인 중...
python --version >nul 2>&1
if errorlevel 1 (
    echo ✗ Python이 설치되어 있지 않습니다!
    echo.
    echo Python 3.8 이상을 설치해주세요:
    echo https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
python --version
echo ✓ Python 확인 완료
echo.

REM 필수 라이브러리 확인
echo [3/4] 필수 라이브러리 확인 중...
python -c "import tkinter" 2>nul
if errorlevel 1 (
    echo ✗ tkinter가 설치되어 있지 않습니다!
    pause
    exit /b 1
)

python -c "import win32api" 2>nul
if errorlevel 1 (
    echo ✗ pywin32가 설치되어 있지 않습니다!
    echo.
    echo 설치하시겠습니까? (Y/N)
    set /p install_choice=
    if /i "%install_choice%"=="Y" (
        echo 설치 중...
        pip install pywin32
    ) else (
        echo 설치를 건너뜁니다. 일부 기능이 제한될 수 있습니다.
    )
    echo.
)

python -c "import cv2" 2>nul
if errorlevel 1 (
    echo ⚠ opencv-python이 설치되어 있지 않습니다.
    echo   (QR 코드 복구 기능이 제한됩니다)
)

python -c "import PIL" 2>nul
if errorlevel 1 (
    echo ⚠ Pillow가 설치되어 있지 않습니다.
    echo   (QR 코드 복구 기능이 제한됩니다)
)

python -c "import pyzbar" 2>nul
if errorlevel 1 (
    echo ⚠ pyzbar가 설치되어 있지 않습니다.
    echo   (QR 코드 복구 기능이 제한됩니다)
)

echo ✓ 라이브러리 확인 완료
echo.

REM 필수 파일 확인
echo [4/4] 필수 파일 확인 중...
if not exist "file_recovery_tool_real.py" (
    echo ✗ file_recovery_tool_real.py 파일이 없습니다!
    pause
    exit /b 1
)

if not exist "partition_recovery.py" (
    echo ⚠ partition_recovery.py 파일이 없습니다.
    echo   (파티션 복구 기능이 제한됩니다)
)

if not exist "vss_recovery.py" (
    echo ⚠ vss_recovery.py 파일이 없습니다.
    echo   (VSS 복구 기능이 제한됩니다)
)

echo ✓ 파일 확인 완료
echo.

echo ========================================
echo   DataAnchor 실행 중...
echo ========================================
echo.

REM 프로그램 실행
python file_recovery_tool_real.py

echo.
echo ========================================
echo   프로그램이 종료되었습니다.
echo ========================================
pause
