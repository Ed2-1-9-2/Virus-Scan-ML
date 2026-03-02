#!/bin/bash

echo "================================="
echo " PORNIRE INTELIGENTĂ AUTO-DETECT"
echo "================================="

ROOT_DIR=$(pwd)
FRONTEND_DIR="m-virus-ui"
BACKEND_VENV="$ROOT_DIR/.venv"
PYTHON_EXE="$BACKEND_VENV/Scripts/python.exe"

# Îi spunem lui Python să citească din tot proiectul, oriunde s-ar afla fișierele
export PYTHONPATH="$ROOT_DIR"

# CĂUTĂM AUTOMAT FIȘIERUL BACKEND-ULUI
echo "Caut fișierul api_backend.py oriunde s-ar ascunde..."
API_FILE=$(find . -name "api_backend.py" -not -path "*/\.venv/*" | head -n 1)

if [ -z "$API_FILE" ]; then
    echo " EROARE : Fișierul 'api_backend.py' NU MAI EXISTĂ în proiect!"
    echo " Verifică în VS Code în stânga dacă nu cumva l-ai șters din greșeală."
    exit 1
fi

CLEAN_PATH=${API_FILE#./}
MODULE_PATH=${CLEAN_PATH%.py}
UVICORN_MODULE="${MODULE_PATH//\//.}:app"

echo "Găsit! S-a ascuns la calea: $API_FILE"
echo "Am generat comanda de pornire: $UVICORN_MODULE"

echo "================================="
echo "PORNIRE APLICAȚIE"
echo "================================="

#  Pornim Frontend-ul 
if [ -d "$FRONTEND_DIR" ]; then
    echo "Pornesc React-ul pe portul 3000 în fundal..."
    (cd "$FRONTEND_DIR" && npm.cmd start) &
fi

sleep 4
start "" "http://localhost:3000"

#  Pornim Backend-ul din ascunzătoarea lui
echo "Pornesc serverul FastAPI..."
echo "--------------------------------------------------------"

"$PYTHON_EXE" -m uvicorn "$UVICORN_MODULE" --host 127.0.0.1 --port 8000

echo "--------------------------------------------------------"