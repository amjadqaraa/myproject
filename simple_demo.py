#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
عرض توضيحي مبسط لأداة تحليل أمان APK
Simple Demo of APK Security Analysis Tool
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from datetime import datetime

# استيراد المكتبات المتوفرة فقط
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich import print as rprint
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None

def print_colored(text, color="white"):
    """طباعة ملونة"""
    if RICH_AVAILABLE:
        if color == "red":
            console.print(f"[red]{text}[/red]")
        elif color == "green":
            console.print(f"[green]{text}[/green]")
        elif color == "yellow":
            console.print(f"[yellow]{text}[/yellow]")
        elif color == "blue":
            console.print(f"[blue]{text}[/blue]")
        else:
            console.print(text)
    else:
        print(text)

def show_legal_warning():
    """عرض التحذير القانوني"""
    warning = """
╔══════════════════════════════════════════════════════════════╗
║                        تحذير قانوني                          ║
║                      LEGAL WARNING                          ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║ هذه الأداة مخصصة للاستخدام الشرعي فقط في:                    ║
║ • البحث الأمني والتعليمي                                     ║
║ • اختبار الاختراق الأخلاقي                                   ║
║ • تدقيق الأمان للتطبيقات المملوكة                            ║
║                                                              ║
║ This tool is intended for legitimate use only in:           ║
║ • Security research and education                           ║
║ • Ethical penetration testing                               ║
║ • Security auditing of owned applications                   ║
║                                                              ║
║ أي استخدام غير قانوني محظور ومسؤولية المستخدم بالكامل        ║
║ Any illegal use is prohibited and user's full responsibility║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    
    if RICH_AVAILABLE:
        console.print(Panel(warning, style="bold red"))
    else:
        print(warning)
    
    response = input("\nهل توافق على الشروط؟ Do you agree to the terms? (y/N): ")
    if response.lower() not in ['y', 'yes', 'نعم']:
        print_colored("تم إلغاء العملية / Operation cancelled", "red")
        sys.exit(1)

def calculate_file_hash(file_path):
    """حساب hash للملف"""
    hashes = {}
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
    except Exception as e:
        hashes['error'] = str(e)
    
    return hashes

def analyze_basic_info(file_path):
    """تحليل المعلومات الأساسية"""
    path = Path(file_path)
    
    if not path.exists():
        return {"error": "الملف غير موجود"}
    
    info = {
        'file_name': path.name,
        'file_size': path.stat().st_size,
        'file_type': 'APK File (Android Package)',
        'creation_time': datetime.fromtimestamp(path.stat().st_ctime).isoformat(),
        'modification_time': datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
        'hashes': calculate_file_hash(file_path)
    }
    
    return info

def detect_vulnerabilities(file_info):
    """كشف الثغرات الأساسية"""
    vulnerabilities = []
    
    # فحص حجم الملف
    if file_info['file_size'] < 1000:
        vulnerabilities.append({
            'type': 'Suspicious File Size',
            'severity': 'متوسط',
            'description': 'حجم الملف صغير جداً، قد يكون ملف تجريبي أو تالف',
            'recommendation': 'تحقق من صحة الملف'
        })
    
    # فحص امتداد الملف
    if not file_info['file_name'].lower().endswith('.apk'):
        vulnerabilities.append({
            'type': 'Invalid File Extension',
            'severity': 'عالي',
            'description': 'امتداد الملف غير صحيح لملف APK',
            'recommendation': 'تأكد من أن الملف هو APK صحيح'
        })
    
    # فحص التوقيت
    creation_time = datetime.fromisoformat(file_info['creation_time'])
    if creation_time > datetime.now():
        vulnerabilities.append({
            'type': 'Future Timestamp',
            'severity': 'منخفض',
            'description': 'تاريخ إنشاء الملف في المستقبل',
            'recommendation': 'تحقق من إعدادات النظام'
        })
    
    return vulnerabilities

def calculate_security_score(vulnerabilities):
    """حساب نقاط الأمان"""
    score = 100
    
    for vuln in vulnerabilities:
        if vuln['severity'] == 'عالي':
            score -= 20
        elif vuln['severity'] == 'متوسط':
            score -= 10
        elif vuln['severity'] == 'منخفض':
            score -= 5
    
    return max(score, 0)

def generate_report(file_info, vulnerabilities, security_score):
    """إنشاء تقرير التحليل"""
    report = {
        'analysis_info': {
            'tool_name': 'APK Security Analyzer Demo',
            'version': '1.0.0',
            'analysis_date': datetime.now().isoformat(),
            'analyst': 'Automated Analysis'
        },
        'file_info': file_info,
        'security_score': security_score,
        'vulnerabilities_count': len(vulnerabilities),
        'vulnerabilities': vulnerabilities,
        'recommendations': [
            'قم بفحص الملف باستخدام أدوات إضافية',
            'تأكد من مصدر الملف الموثوق',
            'اختبر التطبيق في بيئة معزولة',
            'راجع الصلاحيات المطلوبة'
        ]
    }
    
    return report

def save_report(report, output_file):
    """حفظ التقرير"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print_colored(f"خطأ في حفظ التقرير: {e}", "red")
        return False

def display_results(report):
    """عرض النتائج"""
    print_colored("\n" + "="*60, "blue")
    print_colored("🔐 نتائج تحليل أمان APK", "blue")
    print_colored("APK Security Analysis Results", "blue")
    print_colored("="*60, "blue")
    
    # معلومات الملف
    print_colored("\n📁 معلومات الملف:", "yellow")
    file_info = report['file_info']
    print(f"   📄 اسم الملف: {file_info['file_name']}")
    print(f"   📏 حجم الملف: {file_info['file_size']:,} بايت")
    print(f"   🗓️  تاريخ الإنشاء: {file_info['creation_time']}")
    
    # نقاط الأمان
    score = report['security_score']
    print_colored(f"\n📊 نقاط الأمان: {score}/100", "yellow")
    
    if score >= 80:
        print_colored("   ✅ مستوى الأمان: ممتاز", "green")
    elif score >= 60:
        print_colored("   ⚠️  مستوى الأمان: جيد", "yellow")
    else:
        print_colored("   ❌ مستوى الأمان: ضعيف", "red")
    
    # الثغرات
    vulnerabilities = report['vulnerabilities']
    print_colored(f"\n🔍 الثغرات المكتشفة: {len(vulnerabilities)}", "yellow")
    
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = "red" if vuln['severity'] == 'عالي' else "yellow" if vuln['severity'] == 'متوسط' else "blue"
            print_colored(f"\n   {i}. {vuln['type']}", severity_color)
            print(f"      📊 الخطورة: {vuln['severity']}")
            print(f"      📝 الوصف: {vuln['description']}")
            print(f"      💡 التوصية: {vuln['recommendation']}")
    else:
        print_colored("   ✅ لم يتم اكتشاف ثغرات في الفحص الأساسي", "green")
    
    # التوصيات
    print_colored("\n💡 توصيات عامة:", "yellow")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"   {i}. {rec}")
    
    # معلومات إضافية
    print_colored("\n📋 معلومات إضافية:", "yellow")
    if 'hashes' in file_info and 'error' not in file_info['hashes']:
        print(f"   🔒 MD5: {file_info['hashes']['md5']}")
        print(f"   🔒 SHA256: {file_info['hashes']['sha256'][:32]}...")
    
    print_colored("\n" + "="*60, "blue")

def main():
    """الدالة الرئيسية"""
    print_colored("🔐 أداة تحليل أمان APK - عرض توضيحي", "blue")
    print_colored("APK Security Analysis Tool - Demo Version", "blue")
    print_colored("="*60, "blue")
    
    # عرض التحذير القانوني
    show_legal_warning()
    
    # الحصول على مسار الملف
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("\nأدخل مسار ملف APK: ")
    
    if not file_path:
        print_colored("❌ لم يتم تحديد ملف للتحليل", "red")
        sys.exit(1)
    
    print_colored(f"\n🔍 بدء تحليل الملف: {file_path}", "yellow")
    
    try:
        # تحليل المعلومات الأساسية
        print_colored("📋 استخراج المعلومات الأساسية...", "blue")
        file_info = analyze_basic_info(file_path)
        
        if 'error' in file_info:
            print_colored(f"❌ خطأ: {file_info['error']}", "red")
            sys.exit(1)
        
        # كشف الثغرات
        print_colored("🔍 فحص الثغرات الأمنية...", "blue")
        vulnerabilities = detect_vulnerabilities(file_info)
        
        # حساب نقاط الأمان
        print_colored("📊 حساب نقاط الأمان...", "blue")
        security_score = calculate_security_score(vulnerabilities)
        
        # إنشاء التقرير
        print_colored("📄 إنشاء التقرير...", "blue")
        report = generate_report(file_info, vulnerabilities, security_score)
        
        # عرض النتائج
        display_results(report)
        
        # حفظ التقرير
        output_file = f"demo_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        if save_report(report, output_file):
            print_colored(f"\n💾 تم حفظ التقرير في: {output_file}", "green")
        
        print_colored("\n✅ تم الانتهاء من التحليل بنجاح!", "green")
        
    except KeyboardInterrupt:
        print_colored("\n⏹️  تم إيقاف التحليل بواسطة المستخدم", "yellow")
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n❌ خطأ غير متوقع: {e}", "red")
        sys.exit(1)

if __name__ == "__main__":
    main()