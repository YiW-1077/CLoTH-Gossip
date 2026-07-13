#!/bin/bash
cd "$(dirname "$0")"
.venv/bin/streamlit run cloth_sim_viz_app.py --server.port 8501 --browser.serverAddress localhost
