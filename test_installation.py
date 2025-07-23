#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار سريع للتأكد من صحة التثبيت
Quick Test to Verify Installation
"""

import sys
import importlib
from pathlib import Path

def test_python_version():
    """اختبار إصدار Python"""
    print("🐍 اختبار إصدار Python...")
    
    if sys.version_info < (3, 8):
        print(f"❌ إصدار Python قديم: {sys.version}")
        print("يتطلب Python 3.8 أو أحدث")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return True

def test_required_libraries():
    """اختبار المكتبات المطلوبة"""
    print("\n📚 اختبار المكتبات المطلوبة...")
    
    required_libs = [
        'androguard',
        'rich', 
        'pandas',
        'numpy',
        'matplotlib',
        'reportlab',
        'jinja2',
        'requests',
        'colorama',
        'tqdm',
        'click'
    ]
    
    missing_libs = []
    
    for lib in required_libs:
        try:
            importlib.import_module(lib)
            print(f"✅ {lib}")
        except ImportError:
            print(f"❌ {lib} - غير مثبت")
            missing_libs.append(lib)
    
    if missing_libs:
        print(f"\n⚠️  مكتبات مفقودة: {', '.join(missing_libs)}")
        print("تشغيل: pip install -r requirements.txt")
        return False
    
    return True

def test_optional_libraries():
    """اختبار المكتبات الاختيارية"""
    print("\n🔧 اختبار المكتبات الاختيارية...")
    
    optional_libs = {
        'frida': 'للتحليل الديناميكي',
        'yara': 'لكشف البرمجيات الخبيثة',
        'magic': 'لتحديد نوع الملفات'
    }
    
    for lib, description in optional_libs.items():
        try:
            if lib == 'magic':
                import magic
            else:
                importlib.import_module(lib)
            print(f"✅ {lib} - {description}")
        except ImportError:
            print(f"⚠️  {lib} - غير مثبت ({description})")

def test_file_structure():
    """اختبار هيكل الملفات"""
    print("\n�� اختبار هيكل الملفات...")
    
    required_files = [
        'apk_security_analyzer.py',
        'security_rules.py',
        'frida_analyzer.py',
        'requirements.txt',
        'README.md',
        'LICENSE',
        'config.json'
    ]
    
    required_dirs = [
        'analysis_output',
        'samples',
        'tools',
        'logs',
        'templates'
    ]
    
    missing_files = []
    missing_dirs = []
    
    # فحص الملفات
    for file in required_files:
        if Path(file).exists():
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - مفقود")
            missing_files.append(file)
    
    # فحص المجلدات
    for dir in required_dirs:
        if Path(dir).exists():
            print(f"✅ {dir}/")
        else:
            print(f"❌ {dir}/ - مفقود")
            missing_dirs.append(dir)
    
    if missing_files or missing_dirs:
        print(f"\n⚠️  ملفات مفقودة: {missing_files}")
        print(f"⚠️  مجلدات مفقودة: {missing_dirs}")
        return False
    
    return True

def test_main_script():
    """اختبار السكريبت الرئيسي"""
    print("\n🚀 اختبار السكريبت الرئيسي...")
    
    try:
        # محاولة استيراد الوحدات الرئيسية
        from apk_security_analyzer import APKSecurityAnalyzer, LegalWarning
        from security_rules import SecurityRules, AndroidSecurityChecker
        
        print("✅ استيراد الوحدات الرئيسية نجح")
        
        # اختبار إنشاء كائن SecurityRules
        rules = SecurityRules()
        print(f"✅ تم تحميل {len(rules.get_rule_categories())} فئة قواعد أمان")
        
        # اختبار كود بسيط
        test_code = "Log.d('test', 'message');"
        findings = rules.analyze_code(test_code)
        print(f"✅ تحليل الكود يعمل - {len(findings)} نتيجة")
        
        return True
        
    except Exception as e:
        print(f"❌ خطأ في السكريبت الرئيسي: {e}")
        return False

def test_external_tools():
    """اختبار الأدوات الخارجية"""
    print("\n🛠️  اختبار الأدوات الخارجية...")
    
    import subprocess
    
    tools = {
        'java': 'java -version',
        'apktool': 'apktool --version',
        'adb': 'adb version'
    }
    
    for tool, cmd in tools.items():
        try:
            result = subprocess.run(
                cmd.split(), 
                capture_output=True, 
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"✅ {tool}")
            else:
                print(f"⚠️  {tool} - متوفر لكن قد يحتاج إعداد")
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"❌ {tool} - غير متوفر")
        except Exception as e:
            print(f"⚠️  {tool} - خطأ في الاختبار: {e}")

def generate_test_report():
    """إنشاء تقرير الاختبار"""
    print("\n📋 إنشاء تقرير الاختبار...")
    
    report = f"""
# تقرير اختبار التثبيت
# Installation Test Report

التاريخ: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## النتائج:
- Python: {'✅' if sys.version_info >= (3, 8) else '❌'}
- المكتبات الأساسية: تم الفحص
- هيكل الملفات: تم الفحص  
- السكريبت الرئيسي: تم الفحص
- الأدوات الخارجية: تم الفحص

## التوصيات:
1. تأكد من تثبيت جميع المكتبات المطلوبة
2. راجع ملف README.md للتعليمات التفصيلية
3. اختبر الأداة على ملف APK تجريبي

## الدعم:
- راجع ملف README.md
- تحقق من ملف requirements.txt
- شغل install.sh للتثبيت التلقائي
    """
    
    with open('test_report.md', 'w', encoding='utf-8') as f:
        f.write(report)
    
    print("✅ تم حفظ تقرير الاختبار في: test_report.md")

def main():
    """الدالة الرئيسية"""
    print("🔍 اختبار سريع لأداة تحليل أمان APK")
    print("Quick Test for APK Security Analysis Tool")
    print("=" * 60)
    
    tests = [
        ("إصدار Python", test_python_version),
        ("المكتبات المطلوبة", test_required_libraries), 
        ("المكتبات الاختيارية", test_optional_libraries),
        ("هيكل الملفات", test_file_structure),
        ("السكريبت الرئيسي", test_main_script),
        ("الأدوات الخارجية", test_external_tools)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ خطأ في اختبار {test_name}: {e}")
    
    print(f"\n{'='*60}")
    print(f"📊 نتائج الاختبار: {passed}/{total} نجح")
    
    if passed == total:
        print("�� جميع الاختبارات نجحت! الأداة جاهزة للاستخدام")
        print("\nللبدء:")
        print("python3 apk_security_analyzer.py -f your_app.apk")
    elif passed >= total - 2:
        print("⚠️  معظم الاختبارات نجحت، الأداة قابلة للاستخدام مع قيود")
        print("راجع الأخطاء أعلاه وأصلحها إن أمكن")
    else:
        print("❌ عدة اختبارات فشلت، يرجى مراجعة التثبيت")
        print("شغل: ./install.sh للتثبيت التلقائي")
    
    # إنشاء تقرير
    generate_test_report()

if __name__ == "__main__":
    main()
