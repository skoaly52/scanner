#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import platform

def run_command(command, check=True):
    """تنفيذ أمر في سطر الأوامر"""
    try:
        print(f"جاري تنفيذ: {command}")
        result = subprocess.run(command, shell=True, check=check, text=True, capture_output=True)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"خطأ في التنفيذ: {e}")
        if e.stderr:
            print(f"خطأ: {e.stderr}")
        return False

def install_chocolatey():
    """تثبيت Chocolatey مدير الحزم لـ Windows"""
    if run_command('choco --version', check=False):
        print("Chocolatey مثبت مسبقاً")
        return True
    
    print("جاري تثبيت Chocolatey...")
    command = 'Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString(\'https://community.chocolatey.org/install.ps1\'))'
    return run_command(f'powershell -Command "{command}"')

def install_python():
    """التأكد من تثبيت بايثون"""
    if run_command('python --version', check=False) or run_command('py --version', check=False):
        print("بايثون مثبت مسبقاً")
        return True
    
    print("جاري تثبيت بايثون...")
    return run_command('choco install python -y')

def install_git():
    """التأكد من تثبيت Git"""
    if run_command('git --version', check=False):
        print("Git مثبت مسبقاً")
        return True
    
    print("جاري تثبيت Git...")
    return run_command('choco install git -y')

def install_requirements():
    """تثبيت المتطلبات من ملف requirements.txt إذا وجد"""
    if os.path.exists('requirements.txt'):
        print("جاري تثبيت المتطلبات من requirements.txt...")
        return run_command('pip install -r requirements.txt')
    else:
        print("لم يتم العثور على ملف requirements.txt")
        return True

def setup_wsl():
    """إعداد WSL لتشغيل أدوات Kali Linux"""
    print("جاري التحقق من إعداد WSL...")
    
    # التحقق إذا كان WSL مثبتاً
    if run_command('wsl --list --quiet', check=False):
        print("WSL مثبت مسبقاً")
    else:
        print("جاري تثبيت WSL...")
        if not run_command('wsl --install'):
            print("فشل تثبيت WSL. تأكد من تفعيل Virtualization في BIOS")
            return False
    
    # التحقق من وجود توزيعة Kali Linux
    if not run_command('wsl --list | findstr Kali', check=False):
        print("جاري تثبيت Kali Linux على WSL...")
        if not run_command('wsl --install -d Kali-Linux'):
            print("فشل تثبيت Kali Linux. يمكنك تثبيته يدوياً من Microsoft Store")
    
    return True

def main():
    """الدالة الرئيسية"""
    print("=" * 50)
    print("برنامج الإعداد الآلي للأداة")
    print("=" * 50)
    
    # التحقق من نظام التشغيل
    if platform.system() != 'Windows':
        print("هذا البرنامج مخصص لنظام Windows فقط")
        return
    
    # تثبيت المتطلبات الأساسية
    success = True
    success &= install_chocolatey()
    success &= install_python()
    success &= install_git()
    success &= install_requirements()
    
    # اقتراح إعداد WSL للأدوات التي تتطلب Linux
    print("\nهل تريد إعداد WSL لتشغيل أدوات Kali Linux؟ (y/n)")
    choice = input().lower()
    if choice == 'y' or choice == 'yes':
        success &= setup_wsl()
    
    if success:
        print("\n" + "=" * 50)
        print("تم الإعداد بنجاح! ✅")
        print("=" * 50)
    else:
        print("\n" + "=" * 50)
        print("حدثت بعض الأخطاء أثناء الإعداد ❌")
        print("=" * 50)
    
    input("\nاضغط Enter للإغلاق...")

if __name__ == "__main__":
    main()
