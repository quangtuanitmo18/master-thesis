#!/usr/bin/env python3
"""
Launcher for OpenVuln Dashboard.
Checks for dependencies and runs the Streamlit app.
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    # Check if streamlit is installed
    try:
        import streamlit
    except ImportError:
        print("❌ Streamlit is not installed.")
        print("Please install requirements: pip install -r requirements.txt")
        return

    # Path to the dashboard script
    dashboard_script = Path("openvuln_dashboard.py").absolute()
    
    if not dashboard_script.exists():
        print(f"❌ Dashboard script not found: {dashboard_script}")
        return

    print("🚀 Starting OpenVuln Dashboard...")
    print(f"Script: {dashboard_script}")
    
    # Run streamlit
    cmd = [sys.executable, "-m", "streamlit", "run", str(dashboard_script)]
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped.")

if __name__ == "__main__":
    main()
