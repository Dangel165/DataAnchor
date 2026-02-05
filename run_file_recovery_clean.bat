@echo off
echo 캐시 파일 삭제 중...
del /q __pycache__\*.pyc 2>nul
rmdir /q __pycache__ 2>nul

echo 프로그램 실행...
python file_recovery_tool_real.py

pause
