#!/bin/bash
# Streamlit launcher for DINDGA

cd "$(dirname "$0")"
./venv/bin/streamlit run streamlit_app/app.py
