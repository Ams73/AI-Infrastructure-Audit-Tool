@echo off
setlocal
rem Editable installs from pyproject.toml need a recent pip.
python -m pip install --upgrade pip
python -m pip install -e ".[web,ai]"
echo Installation complete.
