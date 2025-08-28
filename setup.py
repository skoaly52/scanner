#!/usr/bin/env python3
"""
Automated Environment Setup Script
This script automates the setup process for development tools on Windows
"""

import os
import sys
import subprocess
import platform
import urllib.request
import tempfile
import ctypes
import time

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_command(command, check=True, shell=True):
    """Execute a command in the command line"""
    try:
        print(f"Executing: {command}")
        result = subprocess.run(command, shell=shell, check=check, 
                              text=True, capture_output=True, encoding='utf-8')
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def install_chocolatey():
    """Install Chocolatey package manager for Windows"""
    if run_command('choco --version', check=False):
        print("Chocolatey is already installed")
        return True
    
    print("Installing Chocolatey...")
    # Using the official Chocolatey install command
    install_cmd = (
        "Set-ExecutionPolicy Bypass -Scope Process -Force; "
        "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
        "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    )
    return run_command(f'powershell -Command "{install_cmd}"')

def install_python():
    """Ensure Python is installed"""
    if run_command('python --version', check=False) or run_command('py --version', check=False):
        print("Python is already installed")
        return True
    
    print("Installing Python via Chocolatey...")
    return run_command('choco install python -y')

def install_git():
    """Ensure Git is installed"""
    if run_command('git --version', check=False):
        print("Git is already installed")
        return True
    
    print("Installing Git via Chocolatey...")
    return run_command('choco install git -y')

def install_vscode():
    """Install Visual Studio Code"""
    if run_command('code --version', check=False):
        print("VS Code is already installed")
        return True
    
    print("Installing Visual Studio Code...")
    return run_command('choco install vscode -y')

def install_requirements():
    """Install requirements from requirements.txt if it exists"""
    if os.path.exists('requirements.txt'):
        print("Installing Python requirements...")
        return run_command('pip install -r requirements.txt')
    else:
        print("No requirements.txt file found")
        return True

def setup_wsl():
    """Set up WSL for running Linux tools"""
    print("Checking WSL setup...")
    
    # Check if WSL is already installed
    if run_command('wsl --list --quiet', check=False):
        print("WSL is already installed")
        return True
    
    print("Installing WSL...")
    if run_command('wsl --install'):
        print("WSL installed successfully. A reboot might be required.")
        return True
    else:
        print("Failed to install WSL. Trying manual installation...")
        return run_command('dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart')

def install_additional_tools():
    """Install additional useful tools"""
    tools = [
        'nodejs',
        'curl',
        '7zip',
        'googlechrome',
        'firefox'
    ]
    
    print("Installing additional development tools...")
    for tool in tools:
        run_command(f'choco install {tool} -y', check=False)
    
    return True

def check_system_requirements():
    """Check if system meets minimum requirements"""
    print("Checking system requirements...")
    
    # Check Windows version
    win_version = platform.version()
    print(f"Windows Version: {win_version}")
    
    # Check architecture
    arch = platform.machine()
    print(f"Architecture: {arch}")
    
    # Check RAM
    try:
        import psutil
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
        print(f"RAM: {ram_gb:.1f} GB")
        if ram_gb < 4:
            print("Warning: Less than 4GB RAM may cause performance issues")
    except:
        print("Install psutil with: pip install psutil for detailed system info")
    
    return True

def main():
    """Main setup function"""
    print("=" * 60)
    print("Automated Development Environment Setup")
    print("=" * 60)
    
    # Check if running on Windows
    if platform.system() != 'Windows':
        print("This script is designed for Windows only")
        return
    
    # Check admin privileges
    if not is_admin():
        print("Please run this script as Administrator for full functionality")
        print("Right-click on Command Prompt or PowerShell and select 'Run as administrator'")
    
    # Setup process
    print("\nStarting setup process...")
    
    success = True
    success &= install_chocolatey()
    success &= install_python()
    success &= install_git()
    success &= install_vscode()
    success &= install_requirements()
    
    # Ask about WSL setup
    print("\nDo you want to set up WSL for Linux tools? (y/n)")
    choice = input().lower().strip()
    if choice in ['y', 'yes']:
        success &= setup_wsl()
    
    # Ask about additional tools
    print("\nDo you want to install additional development tools? (y/n)")
    choice = input().lower().strip()
    if choice in ['y', 'yes']:
        success &= install_additional_tools()
    
    # Final status
    print("\n" + "=" * 60)
    if success:
        print("Setup completed successfully! ✅")
        print("\nNext steps:")
        print("1. Restart your computer if prompted")
        print("2. Open VS Code and install recommended extensions")
        print("3. Run 'git config --global user.name \"Your Name\"'")
        print("4. Run 'git config --global user.email \"your.email@example.com\"'")
    else:
        print("Setup completed with some errors ❌")
        print("Check the messages above for issues")
    
    print("=" * 60)
    input("\nPress Enter to close...")

if __name__ == "__main__":
    main()
