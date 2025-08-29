#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from setuptools.command.install import install
import sys
import subprocess
import importlib
import platform
import os
import time

class CustomInstallCommand(install):
    """Custom installation that checks and installs dependencies automatically"""
    
    def run(self):
        # Check and install dependencies first
        if not self.check_dependencies():
            print("❌ Dependency installation failed. Please install manually: pip install -r requirements.txt")
            sys.exit(1)
        
        # Proceed with normal installation
        install.run(self)
    
    def check_dependencies(self):
        """Check required packages and install missing ones"""
        
        required_packages = [
            'requests>=2.28.0',
            'beautifulsoup4>=4.11.0',
            'urllib3>=1.26.0',
            'cryptography>=38.0.0',
            'idna>=3.0',
            'charset-normalizer>=3.0.0',
            'certifi>=2022.0.0',
            'pillow>=9.0.0',
            'python-dateutil>=2.8.0'
        ]

        # System-specific packages
        system_specific_packages = []
        
        if platform.system() == "Windows":
            system_specific_packages.extend([
                'pywin32>=300',
                'pyinstaller>=5.0.0'
            ])
        elif platform.system() == "Linux":
            # Useful packages for Kali Linux
            system_specific_packages.extend([
                'scapy>=2.4.0',
                'paramiko>=2.0.0',
                'netifaces>=0.10.0'
            ])

        all_packages = required_packages + system_specific_packages
        
        print("🔍 Checking required packages...")
        time.sleep(1)
        
        missing_packages = []
        for package in all_packages:
            try:
                # Extract package name without version
                package_name = package.split('>')[0].split('<')[0].split('=')[0].strip()
                if package_name.lower() == 'pillow':
                    importlib.import_module('PIL')
                else:
                    importlib.import_module(package_name)
                print(f"✅ {package_name} is installed")
            except ImportError:
                missing_packages.append(package)
                print(f"❌ {package_name} is missing")

        if missing_packages:
            print(f"\n📦 Installing {len(missing_packages)} missing packages...")
            try:
                # Install missing packages
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
                print("✅ All packages installed successfully!")
                return True
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install packages: {e}")
                # Try installing one by one
                return self.install_packages_one_by_one(missing_packages)
        else:
            print("✅ All required packages are already installed!")
            return True
    
    def install_packages_one_by_one(self, packages):
        """Install packages one by one to handle individual failures"""
        success = True
        for package in packages:
            try:
                print(f"📦 Installing {package}...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✅ {package} installed successfully!")
            except subprocess.CalledProcessError:
                print(f"⚠️  Warning: Failed to install {package}")
                success = False
        return success

def create_windows_shortcut():
    """Create Windows shortcut after installation"""
    if platform.system() == "Windows":
        try:
            import winshell
            from win32com.client import Dispatch
            
            desktop = winshell.desktop()
            shortcut_path = os.path.join(desktop, "Dark Vulnerability Scanner.lnk")
            
            target = sys.executable
            if hasattr(sys, 'frozen'):
                target = sys.executable
            else:
                target = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            
            wDir = os.path.dirname(target)
            icon = target
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = target
            shortcut.Arguments = "-m dark_scanner.main"
            shortcut.WorkingDirectory = wDir
            shortcut.IconLocation = icon
            shortcut.save()
            
            print("✅ Windows shortcut created on desktop!")
        except ImportError:
            print("⚠️  Could not create Windows shortcut (pywin32 not available)")
        except Exception as e:
            print(f"⚠️  Could not create Windows shortcut: {e}")

def create_linux_desktop_file():
    """Create Linux .desktop file after installation"""
    if platform.system() == "Linux":
        try:
            desktop_file = """[Desktop Entry]
Version=1.0
Type=Application
Name=Dark Vulnerability Scanner
Comment=Advanced Web Vulnerability Scanning Tool
Exec=python3 -m dark_scanner.main
Icon=security-high
Terminal=false
Categories=Security;Network;
Keywords=security;vulnerability;scanner;
"""
            
            desktop_path = os.path.expanduser("~/.local/share/applications/dark-scanner.desktop")
            os.makedirs(os.path.dirname(desktop_path), exist_ok=True)
            
            with open(desktop_path, 'w') as f:
                f.write(desktop_file)
            
            # Make it executable
            os.chmod(desktop_path, 0o755)
            print("✅ Linux desktop file created!")
        except Exception as e:
            print(f"⚠️  Could not create Linux desktop file: {e}")

# Read long description from README
def read_long_description():
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Dark Vulnerability Scanner Pro - Advanced Web Vulnerability Scanning Tool"

setup(
    name="dark-vulnerability-scanner",
    version="1.5.0",
    description="Dark Vulnerability Scanner Pro - Advanced Web Vulnerability Scanning Tool",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    author="Security Team",
    author_email="security@example.com",
    url="https://github.com/yourusername/dark-scanner",
    packages=find_packages(),
    cmdclass={
        'install': CustomInstallCommand,
    },
    install_requires=[
        'requests>=2.28.0',
        'beautifulsoup4>=4.11.0',
        'urllib3>=1.26.0',
        'cryptography>=38.0.0',
        'idna>=3.0',
        'charset-normalizer>=3.0.0',
        'certifi>=2022.0.0',
        'pillow>=9.0.0',
        'python-dateutil>=2.8.0'
    ],
    extras_require={
        'windows': ['pywin32>=300', 'winshell>=1.0.0'],
        'linux': ['scapy>=2.4.0', 'paramiko>=2.0.0', 'netifaces>=0.10.0'],
        'gui': ['pyqt5>=5.15.0', 'pyside2>=5.15.0'],
    },
    entry_points={
        'console_scripts': [
            'dark-scanner=dark_scanner.main:main',
            'dvs=dark_scanner.main:main',  # Short alias
        ],
        'gui_scripts': [
            'dark-scanner-gui=dark_scanner.gui:main',
        ]
    },
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
        'Operating System :: Microsoft :: Windows :: Windows 10',
        'Operating System :: Microsoft :: Windows :: Windows 11',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Unix'
    ],
    keywords=['security', 'vulnerability', 'scanner', 'web', 'pentest', 'hacking'],
    package_data={
        'dark_scanner': [
            'data/*.json',
            'data/*.txt',
            'wordlists/*.txt',
            'icons/*.ico',
            'icons/*.png',
            'config/*.ini'
        ],
    },
    data_files=[
        ('share/applications', ['linux/dark-scanner.desktop']),
        ('share/icons', ['icons/dark-scanner.png']),
    ],
    options={
        'build_exe': {
            'includes': ['tkinter', 'PIL'],
        },
        'bdist_msi': {
            'target_name': 'Dark_Vulnerability_Scanner_Pro.msi',
        }
    },
    project_urls={
        'Documentation': 'https://github.com/yourusername/dark-scanner/wiki',
        'Source': 'https://github.com/yourusername/dark-scanner',
        'Tracker': 'https://github.com/yourusername/dark-scanner/issues',
    }
)

# Post-installation actions
if 'install' in sys.argv:
    print("\n🎉 Installation completed successfully!")
    print("\n📋 Next steps:")
    print("1. Run: dark-scanner")
    print("2. Or run: python -m dark_scanner.main")
    print("3. Check README.md for advanced usage")
    
    # Create platform-specific shortcuts
    if platform.system() == "Windows":
        create_windows_shortcut()
    elif platform.system() == "Linux":
        create_linux_desktop_file()
