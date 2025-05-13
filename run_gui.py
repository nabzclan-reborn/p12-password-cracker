#!/usr/bin/env python3
"""
Quick launcher for the P12 Password Cracker tool
"""

import sys
import os
import subprocess

def check_requirements():
    """Check if all required packages are installed"""
    try:
        import tkinter
        import colorama
        import requests
        from PIL import Image, ImageTk, ImageDraw
        
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Installing required packages...")
        
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("Dependencies installed successfully!")
            return True
        except Exception as e:
            print(f"Error installing dependencies: {e}")
            print("Please install the required packages manually by running:")
            print("pip install -r requirements.txt")
            return False

def main():
    """Main launcher function"""
    print("Starting P12 Password Cracker GUI... look for the open window on your screen.")
    print("star the project on GITHUB if you like it :) - https://github.com/nabzclan-reborn/p12-password-cracker/tree/main ")

    if not check_requirements():
        input("Press Enter to exit...")
        return
    
    try:
        from gui import main as gui_main
        gui_main()
    except Exception as e:
        print(f"Error launching GUI: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
