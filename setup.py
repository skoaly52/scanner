# setup.py - أداة التثبيت الآلي للمكتبات
import os
import sys
import subprocess
import platform

def run_command(command):
    """تنفيذ أمر في سطر الأوامر"""
    try:
        print(f"جاري تنفيذ: {command}")
        result = subprocess.run(command, shell=True, check=True, 
                              text=True, capture_output=True)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
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
            return False
    
    return True

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

if __name__ == "__main__":
    main()
