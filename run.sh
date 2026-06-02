#!/usr/bin/env bash
# Unset GTK env vars that conflict with PyQt6 on Linux (no-op on macOS)
if [[ "$(uname)" == "Linux" ]]; then
    unset GTK_PATH GTK_EXE_PREFIX GIO_MODULE_DIR GSETTINGS_SCHEMA_DIR LOCPATH
    LD_LIBRARY_PATH="" python3 main.py
else
    python3 main.py
fi
