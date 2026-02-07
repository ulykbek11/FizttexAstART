@echo off
echo Starting Ultimate Security Analyzer...

:: Check for OpenAI Key
if "%OPENAI_API_KEY%"=="" (
    echo [WARNING] OPENAI_API_KEY is not set. AI features may not work.
    echo You can set it temporarily with: set OPENAI_API_KEY=sk-...
)

cd backend
echo Installing backend dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Failed to install backend dependencies.
    pause
    exit /b %errorlevel%
)

echo Starting Backend Server...
start "Backend Server" cmd /k "uvicorn app:app --host 0.0.0.0 --port 8000 --reload"

cd ..\frontend
echo Installing frontend dependencies...
call npm install
if %errorlevel% neq 0 (
    echo Failed to install frontend dependencies.
    pause
    exit /b %errorlevel%
)

echo Starting Frontend Server...
start "Frontend Server" cmd /k "npm run dev"

echo Project started! Backend at http://localhost:8000, Frontend usually at http://localhost:5173
pause
