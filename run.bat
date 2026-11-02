@echo off
echo ============================================
echo   Starting AI-NIDS-RAG2
echo ============================================
echo.

call venv\Scripts\activate.bat

echo Starting packet capture (requires Administrator)...
echo A new window will open for this - do not close it.
start "AI-NIDS Capture" powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command cd ''%~dp0''; venv\Scripts\activate; python packet_capture\capture_v2.py'"

echo Waiting for capture to initialize...
timeout /t 5 /nobreak >nul

echo Starting dashboard...
streamlit run dashboard\app.py

pause