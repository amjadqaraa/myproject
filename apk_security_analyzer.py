#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة تحليل أمني متقدمة لملفات APK
APK Security Analysis Tool for Ethical Hacking Research

تحذير قانوني: هذه الأداة مخصصة للاستخدام الشرعي فقط في البحث الأمني والاختبار الأخلاقي.
أي استخدام غير قانوني لهذه الأداة هو مسؤولية المستخدم بالكامل.

Legal Warning: This tool is intended for legitimate security research and ethical testing only.
Any illegal use of this tool is the sole responsibility of the user.

Author: Security Research Team
Version: 1.0.0
License: Educational Use Only
"""

import os
import sys
import json
import hashlib
import zipfile
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
import tempfile
import shutil
import magic
import yara
from typing import Dict, List, Optional, Tuple, Any
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint
from colorama import init, Fore, Back, Style
import warnings
warnings.filterwarnings('ignore')

# تهيئة الألوان
init(autoreset=True)
console = Console()

class LegalWarning:
    """فئة التحذير القانوني"""
    
    @staticmethod
    def display_warning():
        """عرض التحذير القانوني"""
        warning_text = """
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
        console.print(Panel(warning_text, style="bold red"))
        
        response = input("\nهل توافق على الشروط؟ Do you agree to the terms? (y/N): ")
        if response.lower() not in ['y', 'yes', 'نعم']:
            console.print("[red]تم إلغاء العملية / Operation cancelled[/red]")
            sys.exit(1)

class APKSecurityAnalyzer:
    """فئة تحليل أمان APK الرئيسية"""
    
    def __init__(self, apk_path: str, output_dir: str = "analysis_output"):
        """
        تهيئة محلل APK
        
        Args:
            apk_path: مسار ملف APK
            output_dir: مجلد المخرجات
        """
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.temp_dir = None
        self.analysis_results = {}
        self.vulnerabilities = []
        self.security_score = 0
        
        # التحقق من وجود الملف
        if not self.apk_path.exists():
            raise FileNotFoundError(f"ملف APK غير موجود: {apk_path}")
        
        # إنشاء مجلد المخرجات
        self.output_dir.mkdir(exist_ok=True)
        
        # إعداد مجلد مؤقت
        self.temp_dir = Path(tempfile.mkdtemp())
        
        console.print(f"[green]تم تهيئة المحلل بنجاح / Analyzer initialized successfully[/green]")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """تنظيف الملفات المؤقتة"""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def calculate_file_hash(self) -> Dict[str, str]:
        """حساب hash للملف"""
        hashes = {}
        
        with open(self.apk_path, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
        
        return hashes
    
    def extract_basic_info(self) -> Dict[str, Any]:
        """استخراج المعلومات الأساسية"""
        info = {
            'file_name': self.apk_path.name,
            'file_size': self.apk_path.stat().st_size,
            'file_type': magic.from_file(str(self.apk_path)),
            'creation_time': datetime.fromtimestamp(self.apk_path.stat().st_ctime),
            'modification_time': datetime.fromtimestamp(self.apk_path.stat().st_mtime),
            'hashes': self.calculate_file_hash()
        }
        
        return info
    
    def analyze_with_androguard(self) -> Dict[str, Any]:
        """تحليل باستخدام Androguard"""
        try:
            from androguard.core.bytecodes.apk import APK
            from androguard.core.bytecodes.dvm import DalvikVMFormat
            from androguard.core.analysis.analysis import Analysis
            
            console.print("[yellow]بدء التحليل باستخدام Androguard...[/yellow]")
            
            # تحليل APK
            apk = APK(str(self.apk_path))
            
            # استخراج المعلومات الأساسية
            basic_info = {
                'package_name': apk.get_package(),
                'app_name': apk.get_app_name(),
                'version_name': apk.get_androidversion_name(),
                'version_code': apk.get_androidversion_code(),
                'min_sdk': apk.get_min_sdk_version(),
                'target_sdk': apk.get_target_sdk_version(),
                'max_sdk': apk.get_max_sdk_version(),
                'permissions': apk.get_permissions(),
                'activities': apk.get_activities(),
                'services': apk.get_services(),
                'receivers': apk.get_receivers(),
                'providers': apk.get_providers(),
                'main_activity': apk.get_main_activity(),
                'is_signed': apk.is_signed(),
                'certificate': self.extract_certificate_info(apk)
            }
            
            # تحديد نوع التطبيق
            app_type = self.detect_app_framework(apk)
            basic_info['framework'] = app_type
            
            return basic_info
            
        except ImportError:
            console.print("[red]خطأ: مكتبة Androguard غير مثبتة[/red]")
            return {}
        except Exception as e:
            console.print(f"[red]خطأ في تحليل Androguard: {e}[/red]")
            return {}
    
    def detect_app_framework(self, apk) -> str:
        """كشف إطار عمل التطبيق"""
        try:
            # البحث عن ملفات مميزة لكل إطار عمل
            files = apk.get_files()
            
            # Flutter
            if any('flutter' in f.lower() for f in files):
                return "Flutter"
            
            # React Native
            if any('react' in f.lower() or 'bundle.js' in f for f in files):
                return "React Native"
            
            # Xamarin
            if any('xamarin' in f.lower() for f in files):
                return "Xamarin"
            
            # Unity
            if any('unity' in f.lower() or 'libunity.so' in f for f in files):
                return "Unity"
            
            # Cordova/PhoneGap
            if any('cordova' in f.lower() or 'phonegap' in f.lower() for f in files):
                return "Cordova/PhoneGap"
            
            # Kotlin (البحث في الكود)
            dex_files = apk.get_dex()
            if dex_files:
                for dex in dex_files:
                    if b'kotlin' in dex:
                        return "Kotlin"
            
            return "Java (Native Android)"
            
        except Exception:
            return "Unknown"
    
    def extract_certificate_info(self, apk) -> Dict[str, Any]:
        """استخراج معلومات الشهادة"""
        try:
            cert_info = {}
            if apk.is_signed():
                certs = apk.get_certificates()
                if certs:
                    cert = certs[0]  # أول شهادة
                    cert_info = {
                        'subject': str(cert.subject),
                        'issuer': str(cert.issuer),
                        'serial_number': str(cert.serial_number),
                        'not_valid_before': cert.not_valid_before,
                        'not_valid_after': cert.not_valid_after,
                        'signature_algorithm': cert.signature_algorithm_oid._name
                    }
            return cert_info
        except Exception:
            return {}
    
    def analyze_permissions(self, permissions: List[str]) -> Dict[str, Any]:
        """تحليل الصلاحيات"""
        dangerous_permissions = {
            'android.permission.READ_SMS': 'قراءة الرسائل النصية',
            'android.permission.SEND_SMS': 'إرسال الرسائل النصية',
            'android.permission.READ_CONTACTS': 'قراءة جهات الاتصال',
            'android.permission.WRITE_CONTACTS': 'كتابة جهات الاتصال',
            'android.permission.ACCESS_FINE_LOCATION': 'الوصول للموقع الدقيق',
            'android.permission.ACCESS_COARSE_LOCATION': 'الوصول للموقع التقريبي',
            'android.permission.CAMERA': 'استخدام الكاميرا',
            'android.permission.RECORD_AUDIO': 'تسجيل الصوت',
            'android.permission.READ_PHONE_STATE': 'قراءة حالة الهاتف',
            'android.permission.CALL_PHONE': 'إجراء مكالمات',
            'android.permission.READ_CALL_LOG': 'قراءة سجل المكالمات',
            'android.permission.WRITE_CALL_LOG': 'كتابة سجل المكالمات',
            'android.permission.READ_EXTERNAL_STORAGE': 'قراءة التخزين الخارجي',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'كتابة التخزين الخارجي',
            'android.permission.INSTALL_PACKAGES': 'تثبيت التطبيقات',
            'android.permission.DELETE_PACKAGES': 'حذف التطبيقات',
            'android.permission.SYSTEM_ALERT_WINDOW': 'عرض نوافذ النظام',
            'android.permission.BIND_DEVICE_ADMIN': 'إدارة الجهاز',
            'android.permission.INTERNET': 'الوصول للإنترنت'
        }
        
        analysis = {
            'total_permissions': len(permissions),
            'dangerous_permissions': [],
            'normal_permissions': [],
            'unknown_permissions': [],
            'risk_level': 'منخفض'
        }
        
        dangerous_count = 0
        
        for perm in permissions:
            if perm in dangerous_permissions:
                analysis['dangerous_permissions'].append({
                    'permission': perm,
                    'description': dangerous_permissions[perm]
                })
                dangerous_count += 1
            elif perm.startswith('android.permission.'):
                analysis['normal_permissions'].append(perm)
            else:
                analysis['unknown_permissions'].append(perm)
        
        # تحديد مستوى المخاطر
        if dangerous_count > 10:
            analysis['risk_level'] = 'عالي جداً'
        elif dangerous_count > 7:
            analysis['risk_level'] = 'عالي'
        elif dangerous_count > 4:
            analysis['risk_level'] = 'متوسط'
        elif dangerous_count > 2:
            analysis['risk_level'] = 'منخفض إلى متوسط'
        
        return analysis
    
    def detect_security_vulnerabilities(self, apk_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """كشف الثغرات الأمنية"""
        vulnerabilities = []
        
        # فحص الصلاحيات الخطرة
        if 'permissions' in apk_info:
            perm_analysis = self.analyze_permissions(apk_info['permissions'])
            
            if len(perm_analysis['dangerous_permissions']) > 5:
                vulnerabilities.append({
                    'type': 'Excessive Permissions',
                    'severity': 'متوسط',
                    'description': 'التطبيق يطلب صلاحيات خطرة كثيرة',
                    'recommendation': 'مراجعة ضرورة جميع الصلاحيات المطلوبة',
                    'cwe': 'CWE-250'
                })
        
        # فحص إصدار SDK
        if 'min_sdk' in apk_info:
            if apk_info['min_sdk'] and int(apk_info['min_sdk']) < 21:
                vulnerabilities.append({
                    'type': 'Outdated SDK Version',
                    'severity': 'عالي',
                    'description': f'إصدار SDK قديم: {apk_info["min_sdk"]}',
                    'recommendation': 'تحديث الحد الأدنى لإصدار SDK إلى 21 أو أحدث',
                    'cwe': 'CWE-1104'
                })
        
        # فحص التوقيع
        if 'is_signed' in apk_info and not apk_info['is_signed']:
            vulnerabilities.append({
                'type': 'Unsigned APK',
                'severity': 'عالي',
                'description': 'التطبيق غير موقع',
                'recommendation': 'توقيع التطبيق بشهادة صالحة',
                'cwe': 'CWE-347'
            })
        
        # فحص التشفير في النقل
        if 'permissions' in apk_info:
            if 'android.permission.INTERNET' in apk_info['permissions']:
                vulnerabilities.append({
                    'type': 'Network Security',
                    'severity': 'متوسط',
                    'description': 'التطبيق يستخدم الإنترنت - تحقق من استخدام HTTPS',
                    'recommendation': 'التأكد من استخدام HTTPS لجميع الاتصالات',
                    'cwe': 'CWE-319'
                })
        
        # فحص صلاحيات النظام الخطرة
        dangerous_system_perms = [
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.INSTALL_PACKAGES'
        ]
        
        if 'permissions' in apk_info:
            for perm in dangerous_system_perms:
                if perm in apk_info['permissions']:
                    vulnerabilities.append({
                        'type': 'Dangerous System Permission',
                        'severity': 'عالي',
                        'description': f'صلاحية نظام خطرة: {perm}',
                        'recommendation': 'مراجعة ضرورة هذه الصلاحية وتقييد استخدامها',
                        'cwe': 'CWE-250'
                    })
        
        return vulnerabilities
    
    def analyze_with_quark(self) -> Dict[str, Any]:
        """تحليل باستخدام Quark Engine"""
        try:
            console.print("[yellow]بدء التحليل باستخدام Quark Engine...[/yellow]")
            
            # هذا مثال مبسط - في التطبيق الحقيقي نحتاج تثبيت quark-engine
            # وإعداد قواعد الكشف المخصصة
            
            quark_results = {
                'malware_detection': 'نظيف',
                'behavior_analysis': [],
                'api_analysis': [],
                'risk_score': 0
            }
            
            return quark_results
            
        except ImportError:
            console.print("[yellow]تحذير: Quark Engine غير متوفر[/yellow]")
            return {}
        except Exception as e:
            console.print(f"[red]خطأ في تحليل Quark: {e}[/red]")
            return {}
    
    def extract_with_apktool(self) -> bool:
        """فك التطبيق باستخدام apktool"""
        try:
            console.print("[yellow]فك التطبيق باستخدام apktool...[/yellow]")
            
            extract_dir = self.temp_dir / "apktool_output"
            
            # تشغيل apktool
            cmd = f"apktool d {self.apk_path} -o {extract_dir} -f"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                console.print("[green]تم فك التطبيق بنجاح[/green]")
                return True
            else:
                console.print(f"[red]فشل في فك التطبيق: {result.stderr}[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]خطأ في apktool: {e}[/red]")
            return False
    
    def analyze_smali_code(self) -> Dict[str, Any]:
        """تحليل كود Smali"""
        smali_analysis = {
            'suspicious_patterns': [],
            'crypto_usage': [],
            'network_calls': [],
            'file_operations': []
        }
        
        try:
            smali_dir = self.temp_dir / "apktool_output" / "smali"
            
            if not smali_dir.exists():
                return smali_analysis
            
            console.print("[yellow]تحليل كود Smali...[/yellow]")
            
            # أنماط مشبوهة للبحث عنها
            suspicious_patterns = {
                'root_detection': [r'su\s*', r'Superuser', r'root'],
                'anti_debug': [r'Debug', r'debugger', r'isDebuggerConnected'],
                'encryption': [r'encrypt', r'decrypt', r'AES', r'DES', r'RSA'],
                'network': [r'HttpURLConnection', r'Socket', r'URL'],
                'reflection': [r'getDeclaredMethod', r'getMethod', r'invoke'],
                'dynamic_loading': [r'DexClassLoader', r'loadClass'],
                'native_calls': [r'System\.loadLibrary', r'native']
            }
            
            # البحث في ملفات Smali
            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        for category, patterns in suspicious_patterns.items():
                            for pattern in patterns:
                                if any(p in content.lower() for p in pattern.split('|')):
                                    smali_analysis['suspicious_patterns'].append({
                                        'file': str(smali_file.relative_to(smali_dir)),
                                        'category': category,
                                        'pattern': pattern
                                    })
                                    
                except Exception:
                    continue
            
            return smali_analysis
            
        except Exception as e:
            console.print(f"[red]خطأ في تحليل Smali: {e}[/red]")
            return smali_analysis
    
    def calculate_security_score(self) -> int:
        """حساب نقاط الأمان"""
        score = 100  # البداية من 100
        
        # خصم نقاط للثغرات
        for vuln in self.vulnerabilities:
            if vuln['severity'] == 'عالي':
                score -= 20
            elif vuln['severity'] == 'متوسط':
                score -= 10
            elif vuln['severity'] == 'منخفض':
                score -= 5
        
        # خصم إضافي للصلاحيات الخطرة
        if 'permissions_analysis' in self.analysis_results:
            dangerous_count = len(self.analysis_results['permissions_analysis']['dangerous_permissions'])
            score -= min(dangerous_count * 2, 30)
        
        return max(score, 0)
    
    def generate_report_data(self) -> Dict[str, Any]:
        """إنشاء بيانات التقرير"""
        return {
            'basic_info': self.analysis_results.get('basic_info', {}),
            'androguard_analysis': self.analysis_results.get('androguard_analysis', {}),
            'permissions_analysis': self.analysis_results.get('permissions_analysis', {}),
            'vulnerabilities': self.vulnerabilities,
            'security_score': self.security_score,
            'smali_analysis': self.analysis_results.get('smali_analysis', {}),
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def create_html_report(self, report_data: Dict[str, Any]) -> str:
        """إنشاء تقرير HTML"""
        html_template = """
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير تحليل أمان APK</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .vulnerability-high { background-color: #ffebee; border-left: 5px solid #f44336; }
        .vulnerability-medium { background-color: #fff3e0; border-left: 5px solid #ff9800; }
        .vulnerability-low { background-color: #f3e5f5; border-left: 5px solid #9c27b0; }
        .score { font-size: 2em; font-weight: bold; text-align: center; padding: 20px; }
        .score-high { color: #4caf50; }
        .score-medium { color: #ff9800; }
        .score-low { color: #f44336; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 12px; text-align: right; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>تقرير تحليل أمان APK</h1>
            <p>APK Security Analysis Report</p>
            <p>تاريخ التحليل: {{ analysis_timestamp }}</p>
        </div>
        
        <div class="warning">
            <strong>تحذير:</strong> هذا التقرير للأغراض التعليمية والبحثية فقط. لا يجب استخدامه لأغراض ضارة.
        </div>
        
        <div class="section">
            <h2>نقاط الأمان</h2>
            <div class="score {{ score_class }}">{{ security_score }}/100</div>
        </div>
        
        <div class="section">
            <h2>المعلومات الأساسية</h2>
            <table>
                <tr><th>اسم الملف</th><td>{{ basic_info.file_name }}</td></tr>
                <tr><th>حجم الملف</th><td>{{ basic_info.file_size }} بايت</td></tr>
                <tr><th>نوع الملف</th><td>{{ basic_info.file_type }}</td></tr>
                <tr><th>MD5</th><td>{{ basic_info.hashes.md5 }}</td></tr>
                <tr><th>SHA256</th><td>{{ basic_info.hashes.sha256 }}</td></tr>
            </table>
        </div>
        
        {% if androguard_analysis %}
        <div class="section">
            <h2>معلومات التطبيق</h2>
            <table>
                <tr><th>اسم الحزمة</th><td>{{ androguard_analysis.package_name }}</td></tr>
                <tr><th>اسم التطبيق</th><td>{{ androguard_analysis.app_name }}</td></tr>
                <tr><th>إصدار التطبيق</th><td>{{ androguard_analysis.version_name }}</td></tr>
                <tr><th>إطار العمل</th><td>{{ androguard_analysis.framework }}</td></tr>
                <tr><th>الحد الأدنى SDK</th><td>{{ androguard_analysis.min_sdk }}</td></tr>
                <tr><th>SDK المستهدف</th><td>{{ androguard_analysis.target_sdk }}</td></tr>
                <tr><th>موقع</th><td>{{ androguard_analysis.is_signed }}</td></tr>
            </table>
        </div>
        {% endif %}
        
        <div class="section">
            <h2>الثغرات الأمنية المكتشفة</h2>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability-{{ vuln.severity_class }}">
                <h3>{{ vuln.type }}</h3>
                <p><strong>الخطورة:</strong> {{ vuln.severity }}</p>
                <p><strong>الوصف:</strong> {{ vuln.description }}</p>
                <p><strong>التوصية:</strong> {{ vuln.recommendation }}</p>
                {% if vuln.cwe %}<p><strong>CWE:</strong> {{ vuln.cwe }}</p>{% endif %}
            </div>
            {% endfor %}
        </div>
        
        {% if permissions_analysis %}
        <div class="section">
            <h2>تحليل الصلاحيات</h2>
            <p><strong>إجمالي الصلاحيات:</strong> {{ permissions_analysis.total_permissions }}</p>
            <p><strong>مستوى المخاطر:</strong> {{ permissions_analysis.risk_level }}</p>
            
            <h3>الصلاحيات الخطرة</h3>
            <ul>
            {% for perm in permissions_analysis.dangerous_permissions %}
                <li>{{ perm.permission }} - {{ perm.description }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <div class="section">
            <h2>ملاحظات إضافية</h2>
            <ul>
                <li>هذا التحليل يعتمد على الفحص الثابت للتطبيق</li>
                <li>قد تحتاج لتحليل ديناميكي إضافي للحصول على صورة كاملة</li>
                <li>بعض الثغرات قد تكون إيجابية خاطئة</li>
                <li>يُنصح بمراجعة الكود المصدري للتأكد من النتائج</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>توصيات الأمان</h2>
            <ul>
                <li>تحديث SDK إلى أحدث إصدار</li>
                <li>تقليل الصلاحيات المطلوبة</li>
                <li>استخدام HTTPS لجميع الاتصالات</li>
                <li>تطبيق تشفير قوي للبيانات الحساسة</li>
                <li>إجراء اختبارات أمان دورية</li>
            </ul>
        </div>
    </div>
</body>
</html>
        """
        
        from jinja2 import Template
        
        # تحديد فئة النقاط
        score_class = "score-high" if self.security_score >= 80 else "score-medium" if self.security_score >= 60 else "score-low"
        
        # إضافة فئات الخطورة
        for vuln in report_data['vulnerabilities']:
            if vuln['severity'] == 'عالي':
                vuln['severity_class'] = 'high'
            elif vuln['severity'] == 'متوسط':
                vuln['severity_class'] = 'medium'
            else:
                vuln['severity_class'] = 'low'
        
        template = Template(html_template)
        html_content = template.render(
            **report_data,
            score_class=score_class
        )
        
        return html_content
    
    def run_analysis(self) -> Dict[str, Any]:
        """تشغيل التحليل الكامل"""
        console.print("[bold blue]بدء التحليل الشامل لملف APK...[/bold blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # المرحلة 1: المعلومات الأساسية
            task1 = progress.add_task("استخراج المعلومات الأساسية...", total=None)
            self.analysis_results['basic_info'] = self.extract_basic_info()
            progress.update(task1, completed=True)
            
            # المرحلة 2: تحليل Androguard
            task2 = progress.add_task("تحليل باستخدام Androguard...", total=None)
            androguard_results = self.analyze_with_androguard()
            self.analysis_results['androguard_analysis'] = androguard_results
            progress.update(task2, completed=True)
            
            # المرحلة 3: تحليل الصلاحيات
            if 'permissions' in androguard_results:
                task3 = progress.add_task("تحليل الصلاحيات...", total=None)
                self.analysis_results['permissions_analysis'] = self.analyze_permissions(
                    androguard_results['permissions']
                )
                progress.update(task3, completed=True)
            
            # المرحلة 4: كشف الثغرات
            task4 = progress.add_task("كشف الثغرات الأمنية...", total=None)
            self.vulnerabilities = self.detect_security_vulnerabilities(androguard_results)
            progress.update(task4, completed=True)
            
            # المرحلة 5: فك التطبيق وتحليل Smali
            task5 = progress.add_task("فك التطبيق وتحليل الكود...", total=None)
            if self.extract_with_apktool():
                self.analysis_results['smali_analysis'] = self.analyze_smali_code()
            progress.update(task5, completed=True)
            
            # المرحلة 6: تحليل Quark
            task6 = progress.add_task("تحليل متقدم باستخدام Quark...", total=None)
            self.analysis_results['quark_analysis'] = self.analyze_with_quark()
            progress.update(task6, completed=True)
            
            # المرحلة 7: حساب النقاط
            task7 = progress.add_task("حساب نقاط الأمان...", total=None)
            self.security_score = self.calculate_security_score()
            progress.update(task7, completed=True)
        
        console.print("[bold green]تم الانتهاء من التحليل بنجاح![/bold green]")
        return self.generate_report_data()
    
    def save_report(self, report_data: Dict[str, Any]) -> Tuple[str, str]:
        """حفظ التقرير"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # حفظ JSON
        json_file = self.output_dir / f"apk_analysis_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2, default=str)
        
        # حفظ HTML
        html_content = self.create_html_report(report_data)
        html_file = self.output_dir / f"apk_analysis_{timestamp}.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(json_file), str(html_file)

def main():
    """الدالة الرئيسية"""
    # عرض التحذير القانوني
    LegalWarning.display_warning()
    
    # إعداد المعاملات
    parser = argparse.ArgumentParser(
        description='أداة تحليل أمان APK للبحث الأخلاقي',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة الاستخدام:
  python apk_security_analyzer.py -f app.apk
  python apk_security_analyzer.py -f app.apk -o my_analysis
  python apk_security_analyzer.py -f app.apk --verbose
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='مسار ملف APK')
    parser.add_argument('-o', '--output', default='analysis_output', help='مجلد المخرجات')
    parser.add_argument('--verbose', action='store_true', help='عرض تفاصيل أكثر')
    
    args = parser.parse_args()
    
    try:
        # بدء التحليل
        with APKSecurityAnalyzer(args.file, args.output) as analyzer:
            report_data = analyzer.run_analysis()
            json_file, html_file = analyzer.save_report(report_data)
            
            # عرض النتائج
            console.print("\n[bold green]تم الانتهاء من التحليل![/bold green]")
            console.print(f"[blue]نقاط الأمان: {analyzer.security_score}/100[/blue]")
            console.print(f"[blue]عدد الثغرات المكتشفة: {len(analyzer.vulnerabilities)}[/blue]")
            console.print(f"[blue]تقرير JSON: {json_file}[/blue]")
            console.print(f"[blue]تقرير HTML: {html_file}[/blue]")
            
            # عرض الثغرات الحرجة
            critical_vulns = [v for v in analyzer.vulnerabilities if v['severity'] == 'عالي']
            if critical_vulns:
                console.print(f"\n[bold red]تحذير: تم اكتشاف {len(critical_vulns)} ثغرة حرجة![/bold red]")
                for vuln in critical_vulns[:3]:  # عرض أول 3 ثغرات
                    console.print(f"  • {vuln['type']}: {vuln['description']}")
    
    except FileNotFoundError as e:
        console.print(f"[red]خطأ: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]تم إلغاء العملية بواسطة المستخدم[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]خطأ غير متوقع: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
