<<<<<<< HEAD
# setup.py - أداة التثبيت الآلي للمكتبات
=======
# setup.py - Cross-Platform Automatic Library Installer
>>>>>>> b3a84e1 (Add README file)
import os
import sys
import subprocess
import platform

def run_command(command):
<<<<<<< HEAD
    """تنفيذ أمر في سطر الأوامر"""
    try:
        print(f"جاري تنفيذ: {command}")
        result = subprocess.run(command, shell=True, check=True, 
                              text=True, capture_output=True)
=======
    """Execute a command in the command line"""
    try:
        print(f"Running: {command}")
        result = subprocess.run(command, shell=True, check=True, 
                                text=True, capture_output=True)
>>>>>>> b3a84e1 (Add README file)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
<<<<<<< HEAD
        print(f"خطأ في التنفيذ: {e}")
        if e.stderr:
            print(f"خطأ: {e.stderr}")
        return False

def check_python():
    """التحقق من تثبيت بايثون"""
    try:
        subprocess.run([sys.executable, "--version"], check=True, capture_output=True)
        print("✅ بايثون مثبت")
        return True
    except:
        print("❌ بايثون غير مثبت")
        print("⏬ يرجى تثبيت بايثون من: https://python.org")
        return False

def install_libraries():
    """تثبيت المكتبات المطلوبة"""
    libraries = ["requests", "beautifulsoup4", "selenium", "colorama"]
    
    print("📦 جاري تثبيت المكتبات المطلوبة...")
    print("المكتبات:", ", ".join(libraries))
    
    for lib in libraries:
        print(f"\nجارٍ تثبيت {lib}...")
        if run_command(f"{sys.executable} -m pip install {lib}"):
            print(f"✅ تم تثبيت {lib} بنجاح")
        else:
            print(f"❌ فشل تثبيت {lib}")
=======
        print(f"Execution error: {e}")
        if e.stderr:
            print(f"Error: {e.stderr}")
        return False

def check_python():
    """Check if Python is installed"""
    try:
        subprocess.run([sys.executable, "--version"], check=True, capture_output=True)
        print("✅ Python is installed")
        return True
    except:
        print("❌ Python is not installed")
        print("⏬ Please install Python from: https://python.org")
        return False

def upgrade_pip():
    """Upgrade pip to the latest version"""
    print("🔄 Upgrading pip...")
    return run_command(f"{sys.executable} -m pip install --upgrade pip")

def install_libraries():
    """Install required libraries"""
    libraries = ["requests", "beautifulsoup4", "selenium", "colorama", "sv-ttk"]
    
    print("📦 Installing required libraries...")
    print("Libraries:", ", ".join(libraries))
    
    for lib in libraries:
        print(f"\nInstalling {lib}...")
        if run_command(f"{sys.executable} -m pip install {lib}"):
            print(f"✅ {lib} installed successfully")
        else:
            print(f"❌ Failed to install {lib}")
>>>>>>> b3a84e1 (Add README file)
            return False
    
    return True

<<<<<<< HEAD
def upgrade_pip():
    """تحديث pip إلى آخر إصدار"""
    print("🔄 جاري تحديث pip...")
    return run_command(f"{sys.executable} -m pip install --upgrade pip")

def main():
    """الدالة الرئيسية"""
    print("=" * 50)
    print("أداة تثبيت المكتبات الآلية")
    print("=" * 50)
    
    # التحقق من نظام التشغيل
    if platform.system() != "Windows":
        print("⚠️  هذه الأداة مصممة لنظام Windows")
        return
    
    # التحقق من تثبيت بايثون
    if not check_python():
        return
    
    # تحديث pip
    upgrade_pip()
    
    # تثبيت المكتبات
    if install_libraries():
        print("\n" + "=" * 50)
        print("✅ تم تثبيت جميع المكتبات بنجاح!")
        print("المكتبات المثبتة:")
        print("- requests: للتعامل مع طلبات HTTP")
        print("- beautifulsoup4: لتحليل HTML")
        print("- selenium: لأتمتة المتصفح")
        print("- colorama: للألوان في سطر الأوامر")
    else:
        print("\n" + "=" * 50)
        print("❌ فشل تثبيت بعض المكتبات")
    
    print("=" * 50)
    input("\nاضغط Enter للإغلاق...")
=======
def main():
    """Main function"""
    print("=" * 50)
    print("Cross-Platform Automatic Library Installer")
    print("=" * 50)
    
    os_type = platform.system()
    print(f"Detected OS: {os_type}")

    # Check Python installation
    if not check_python():
        return
    
    # Upgrade pip
    upgrade_pip()
    
    # Install libraries
    if install_libraries():
        print("\n" + "=" * 50)
        print("✅ All libraries installed successfully!")
        print("Installed libraries:")
        print("- requests: for HTTP requests")
        print("- beautifulsoup4: for HTML parsing")
        print("- selenium: for browser automation")
        print("- colorama: for command-line colors")
        print("- sv-ttk: for modern Tkinter themes")
    else:
        print("\n" + "=" * 50)
        print("❌ Failed to install some libraries")
    
    print("=" * 50)
    input("\nPress Enter to exit...")
>>>>>>> b3a84e1 (Add README file)

if __name__ == "__main__":
    main()
