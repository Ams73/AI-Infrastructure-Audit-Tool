@echo off
setlocal
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements_web.txt
python -m pip install -e .
echo Installation complete.
