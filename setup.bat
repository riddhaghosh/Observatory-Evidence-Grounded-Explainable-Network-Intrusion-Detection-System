@echo off
echo ============================================
echo   AI-NIDS-RAG2 - First-Time Setup
echo ============================================
echo.

echo Checking for Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.11 from python.org
    echo Make sure to check "Add python.exe to PATH" during install.
    pause
    exit /b 1
)

echo Creating virtual environment...
python -m venv venv

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Upgrading pip...
pip install --upgrade pip

echo Installing dependencies (this may take a few minutes)...
pip install -r requirements.txt

echo.
echo ============================================
echo   API Key Setup
echo ============================================
echo This app uses Groq (free) for AI explanations.
echo Get a free key at: https://console.groq.com/keys
echo.
set /p GROQKEY="Paste your Groq API key here: "

echo GROQ_API_KEY=%GROQKEY%> .env

echo.
echo ============================================
echo   Setup complete!
echo   Run 'run.bat' to start the app.
echo ============================================
pause