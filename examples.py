#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أمثلة شاملة لاستخدام أداة تحليل أمان APK
Comprehensive Examples for APK Security Analysis Tool Usage
"""

import os
import sys
import json
from pathlib import Path
from apk_security_analyzer import APKSecurityAnalyzer, LegalWarning
from security_rules import SecurityRules, AndroidSecurityChecker
from frida_analyzer import FridaAnalyzer

def example_basic_analysis():
    """مثال: التحليل الأساسي لملف APK"""
    print("=" * 60)
    print("مثال 1: التحليل الأساسي")
    print("Example 1: Basic Analysis")
    print("=" * 60)
    
    # عرض التحذير القانوني
    LegalWarning.display_warning()
    
    # مسار ملف APK (يجب أن يكون موجوداً)
    apk_path = "samples/example_app.apk"
    
    if not Path(apk_path).exists():
        print(f"⚠️  ملف APK غير موجود: {apk_path}")
        print("يرجى وضع ملف APK في مجلد samples/ للاختبار")
        return
    
    try:
        # إنشاء محلل APK
        with APKSecurityAnalyzer(apk_path, "analysis_output/basic_example") as analyzer:
            # تشغيل التحليل
            report_data = analyzer.run_analysis()
            
            # حفظ التقرير
            json_file, html_file = analyzer.save_report(report_data)
            
            # عرض النتائج
            print(f"\n✅ تم التحليل بنجاح!")
            print(f"�� نقاط الأمان: {analyzer.security_score}/100")
            print(f"🔍 عدد الثغرات: {len(analyzer.vulnerabilities)}")
            print(f"📄 تقرير JSON: {json_file}")
            print(f"🌐 تقرير HTML: {html_file}")
            
    except Exception as e:
        print(f"❌ خطأ في التحليل: {e}")

def example_advanced_analysis():
    """مثال: التحليل المتقدم مع قواعد مخصصة"""
    print("=" * 60)
    print("مثال 2: التحليل المتقدم مع قواعد مخصصة")
    print("Example 2: Advanced Analysis with Custom Rules")
    print("=" * 60)
    
    apk_path = "samples/banking_app.apk"
    
    if not Path(apk_path).exists():
        print(f"⚠️  ملف APK غير موجود: {apk_path}")
        return
    
    try:
        with APKSecurityAnalyzer(apk_path, "analysis_output/advanced_example") as analyzer:
            # تشغيل التحليل الأساسي
            report_data = analyzer.run_analysis()
            
            # تحليل إضافي بقواعد مخصصة
            security_rules = SecurityRules()
            
            # فحص ملفات Smali إذا تم فكها
            smali_dir = analyzer.temp_dir / "apktool_output" / "smali"
            if smali_dir.exists():
                print("🔍 تحليل كود Smali بقواعد مخصصة...")
                
                custom_findings = []
                for smali_file in smali_dir.rglob("*.smali"):
                    try:
                        with open(smali_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            findings = security_rules.analyze_code(content, str(smali_file))
                            custom_findings.extend(findings)
                    except Exception:
                        continue
                
                # إضافة النتائج المخصصة للتقرير
                report_data['custom_analysis'] = {
                    'total_findings': len(custom_findings),
                    'findings': custom_findings[:10],  # أول 10 نتائج
                    'severity_stats': security_rules.get_severity_stats(custom_findings)
                }
                
                print(f"🎯 تم اكتشاف {len(custom_findings)} نمط مشبوه")
            
            # حفظ التقرير المحدث
            json_file, html_file = analyzer.save_report(report_data)
            
            print(f"\n✅ التحليل المتقدم مكتمل!")
            print(f"📊 نقاط الأمان: {analyzer.security_score}/100")
            print(f"🔍 النتائج المخصصة: {len(custom_findings) if 'custom_findings' in locals() else 0}")
            
    except Exception as e:
        print(f"❌ خطأ في التحليل المتقدم: {e}")

def example_batch_analysis():
    """مثال: تحليل متعدد الملفات"""
    print("=" * 60)
    print("مثال 3: تحليل متعدد الملفات")
    print("Example 3: Batch Analysis")
    print("=" * 60)
    
    samples_dir = Path("samples")
    if not samples_dir.exists():
        print("⚠️  مجلد samples غير موجود")
        return
    
    apk_files = list(samples_dir.glob("*.apk"))
    if not apk_files:
        print("⚠️  لا توجد ملفات APK في مجلد samples")
        return
    
    results_summary = []
    
    for apk_file in apk_files:
        print(f"\n🔍 تحليل: {apk_file.name}")
        
        try:
            output_dir = f"analysis_output/batch_{apk_file.stem}"
            
            with APKSecurityAnalyzer(str(apk_file), output_dir) as analyzer:
                report_data = analyzer.run_analysis()
                
                # تجميع النتائج
                summary = {
                    'file_name': apk_file.name,
                    'security_score': analyzer.security_score,
                    'vulnerabilities_count': len(analyzer.vulnerabilities),
                    'high_severity_count': len([v for v in analyzer.vulnerabilities if v['severity'] == 'عالي']),
                    'package_name': report_data.get('androguard_analysis', {}).get('package_name', 'Unknown'),
                    'framework': report_data.get('androguard_analysis', {}).get('framework', 'Unknown')
                }
                
                results_summary.append(summary)
                
                # حفظ التقرير الفردي
                analyzer.save_report(report_data)
                
                print(f"   ✅ نقاط الأمان: {analyzer.security_score}/100")
                print(f"   🔍 ثغرات: {len(analyzer.vulnerabilities)}")
                
        except Exception as e:
            print(f"   ❌ خطأ: {e}")
            results_summary.append({
                'file_name': apk_file.name,
                'error': str(e)
            })
    
    # حفظ ملخص النتائج
    summary_file = "analysis_output/batch_summary.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(results_summary, f, ensure_ascii=False, indent=2)
    
    print(f"\n📊 ملخص التحليل المتعدد:")
    print(f"   📁 ملفات محللة: {len(apk_files)}")
    print(f"   ✅ نجح: {len([r for r in results_summary if 'error' not in r])}")
    print(f"   ❌ فشل: {len([r for r in results_summary if 'error' in r])}")
    print(f"   📄 ملف الملخص: {summary_file}")

def example_dynamic_analysis():
    """مثال: التحليل الديناميكي باستخدام Frida"""
    print("=" * 60)
    print("مثال 4: التحليل الديناميكي")
    print("Example 4: Dynamic Analysis")
    print("=" * 60)
    
    # اسم حزمة التطبيق للتحليل
    package_name = "com.example.testapp"
    
    print(f"🔍 التحليل الديناميكي للتطبيق: {package_name}")
    print("⚠️  يتطلب جهاز Android متصل مع صلاحيات Root")
    
    try:
        analyzer = FridaAnalyzer(package_name)
        
        # التحقق من إعداد Frida
        if not analyzer.check_frida_setup():
            print("❌ إعداد Frida غير صحيح")
            return
        
        print("✅ إعداد Frida صحيح")
        
        # تشغيل التحليل الديناميكي
        print("🚀 بدء التحليل الديناميكي...")
        results = analyzer.run_dynamic_analysis(analysis_duration=30)
        
        if 'error' in results:
            print(f"❌ خطأ في التحليل: {results['error']}")
            return
        
        # إنشاء تقرير
        report = analyzer.generate_dynamic_report(results)
        
        # حفظ التقرير
        report_file = f"analysis_output/dynamic_{package_name}.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✅ التحليل الديناميكي مكتمل!")
        print(f"📄 تقرير ديناميكي: {report_file}")
        
    except Exception as e:
        print(f"❌ خطأ في التحليل الديناميكي: {e}")

def example_custom_vulnerability_detection():
    """مثال: كشف ثغرات مخصصة"""
    print("=" * 60)
    print("مثال 5: كشف ثغرات مخصصة")
    print("Example 5: Custom Vulnerability Detection")
    print("=" * 60)
    
    # كود مثال للاختبار
    test_code = """
public class PaymentActivity extends Activity {
    private boolean isPremium = true; // خطر: قيمة مباشرة
    private String apiKey = "sk_live_1234567890"; // خطر: API key مكشوف
    
    public void verifyPayment() {
        if (BuildConfig.DEBUG) { // خطر: فحص debug
            isPremium = true;
        }
        
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(); // خطر: HTTP
        Log.d("Payment", "User premium status: " + isPremium); // خطر: logging
    }
    
    public void executeCommand(String cmd) {
        Runtime.getRuntime().exec(cmd); // خطر: RCE
    }
}
    """
    
    # تحليل الكود بقواعد مخصصة
    security_rules = SecurityRules()
    findings = security_rules.analyze_code(test_code, "PaymentActivity.java")
    
    print(f"🔍 تحليل كود الاختبار...")
    print(f"📊 عدد الثغرات المكتشفة: {len(findings)}")
    
    # عرض النتائج
    for finding in findings:
        severity_color = {
            'عالي جداً': '🔴',
            'عالي': '🟠', 
            'متوسط': '🟡',
            'منخفض': '🟢'
        }.get(finding['severity'], '⚪')
        
        print(f"\n{severity_color} {finding['rule_name']}")
        print(f"   📋 الوصف: {finding['description']}")
        print(f"   📊 الخطورة: {finding['severity']}")
        print(f"   🔍 النمط: {finding['pattern']}")
        print(f"   📍 السطر: {finding['line_number']}")
        print(f"   💡 CWE: {finding['cwe']}")
    
    # إحصائيات الخطورة
    severity_stats = security_rules.get_severity_stats(findings)
    print(f"\n📊 إحصائيات الخطورة:")
    for severity, count in severity_stats.items():
        if count > 0:
            print(f"   {severity}: {count}")

def example_comprehensive_report():
    """مثال: تقرير شامل مع جميع الميزات"""
    print("=" * 60)
    print("مثال 6: تقرير شامل")
    print("Example 6: Comprehensive Report")
    print("=" * 60)
    
    apk_path = "samples/comprehensive_test.apk"
    
    if not Path(apk_path).exists():
        print(f"⚠️  ملف APK غير موجود: {apk_path}")
        print("سيتم إنشاء تقرير تجريبي...")
        
        # إنشاء بيانات تجريبية
        demo_data = {
            'basic_info': {
                'file_name': 'demo_app.apk',
                'file_size': 15728640,
                'file_type': 'Android application package',
                'hashes': {
                    'md5': 'a1b2c3d4e5f6789012345678901234567',
                    'sha256': 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890'
                }
            },
            'androguard_analysis': {
                'package_name': 'com.example.demoapp',
                'app_name': 'Demo Security App',
                'version_name': '1.0.0',
                'framework': 'Java (Native Android)',
                'min_sdk': '21',
                'target_sdk': '33',
                'is_signed': True,
                'permissions': [
                    'android.permission.INTERNET',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.READ_SMS',
                    'android.permission.CAMERA'
                ]
            },
            'vulnerabilities': [
                {
                    'type': 'Payment Bypass',
                    'severity': 'عالي',
                    'description': 'تم اكتشاف نمط يمكن استغلاله لتجاوز نظام الدفع',
                    'recommendation': 'تطبيق تحقق صارم من حالة الدفع على الخادم',
                    'cwe': 'CWE-840'
                },
                {
                    'type': 'Data Leakage',
                    'severity': 'متوسط',
                    'description': 'تسجيل بيانات حساسة في ملفات السجل',
                    'recommendation': 'إزالة جميع عبارات التسجيل من النسخة النهائية',
                    'cwe': 'CWE-200'
                }
            ],
            'security_score': 72,
            'analysis_timestamp': '2024-01-15T10:30:00'
        }
        
        # إنشاء تقرير HTML تجريبي
        from jinja2 import Template
        
        html_template = """
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <title>تقرير تحليل أمان APK - تجريبي</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .header { text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .score { font-size: 3em; font-weight: bold; text-align: center; color: #ff9800; }
        .vulnerability { background: #ffebee; border-left: 5px solid #f44336; padding: 15px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: right; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>تقرير تحليل أمان APK</h1>
            <p>نموذج تجريبي - Demo Report</p>
        </div>
        
        <div class="section">
            <h2>نقاط الأمان</h2>
            <div class="score">{{ security_score }}/100</div>
        </div>
        
        <div class="section">
            <h2>المعلومات الأساسية</h2>
            <table>
                <tr><th>اسم التطبيق</th><td>{{ androguard_analysis.app_name }}</td></tr>
                <tr><th>اسم الحزمة</th><td>{{ androguard_analysis.package_name }}</td></tr>
                <tr><th>الإصدار</th><td>{{ androguard_analysis.version_name }}</td></tr>
                <tr><th>إطار العمل</th><td>{{ androguard_analysis.framework }}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>الثغرات المكتشفة</h2>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability">
                <h3>{{ vuln.type }}</h3>
                <p><strong>الخطورة:</strong> {{ vuln.severity }}</p>
                <p><strong>الوصف:</strong> {{ vuln.description }}</p>
                <p><strong>التوصية:</strong> {{ vuln.recommendation }}</p>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>خلاصة التحليل</h2>
            <ul>
                <li>تم اكتشاف {{ vulnerabilities|length }} ثغرة أمنية</li>
                <li>نقاط الأمان: {{ security_score }}/100</li>
                <li>يُنصح بمراجعة الثغرات عالية الخطورة فوراً</li>
                <li>تطبيق التوصيات المقترحة لتحسين الأمان</li>
            </ul>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(**demo_data)
        
        # حفظ التقرير التجريبي
        demo_report_file = "analysis_output/demo_comprehensive_report.html"
        os.makedirs("analysis_output", exist_ok=True)
        
        with open(demo_report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ تم إنشاء تقرير تجريبي: {demo_report_file}")
        
        return
    
    # إذا كان الملف موجوداً، قم بالتحليل الحقيقي
    try:
        with APKSecurityAnalyzer(apk_path, "analysis_output/comprehensive") as analyzer:
            report_data = analyzer.run_analysis()
            json_file, html_file = analyzer.save_report(report_data)
            
            print(f"✅ التقرير الشامل مكتمل!")
            print(f"📄 تقرير JSON: {json_file}")
            print(f"🌐 تقرير HTML: {html_file}")
            
    except Exception as e:
        print(f"❌ خطأ في التحليل الشامل: {e}")

def main():
    """الدالة الرئيسية لتشغيل الأمثلة"""
    print("🔐 أداة تحليل أمان APK - أمثلة الاستخدام")
    print("APK Security Analysis Tool - Usage Examples")
    print("=" * 80)
    
    examples = {
        '1': ('التحليل الأساسي', example_basic_analysis),
        '2': ('التحليل المتقدم', example_advanced_analysis),
        '3': ('التحليل المتعدد', example_batch_analysis),
        '4': ('التحليل الديناميكي', example_dynamic_analysis),
        '5': ('كشف ثغرات مخصصة', example_custom_vulnerability_detection),
        '6': ('تقرير شامل', example_comprehensive_report),
        'all': ('تشغيل جميع الأمثلة', None)
    }
    
    print("\nالأمثلة المتاحة:")
    for key, (name, _) in examples.items():
        print(f"  {key}. {name}")
    
    choice = input("\nاختر مثال للتشغيل (أو 'all' لتشغيل الكل): ").strip()
    
    if choice == 'all':
        for key, (name, func) in examples.items():
            if func:  # تجاهل 'all'
                print(f"\n{'='*20} تشغيل {name} {'='*20}")
                try:
                    func()
                except KeyboardInterrupt:
                    print("\n⏹️  تم إيقاف المثال بواسطة المستخدم")
                    break
                except Exception as e:
                    print(f"❌ خطأ في {name}: {e}")
                
                input("\nاضغط Enter للمتابعة...")
    
    elif choice in examples and examples[choice][1]:
        name, func = examples[choice]
        print(f"\n{'='*20} تشغيل {name} {'='*20}")
        try:
            func()
        except KeyboardInterrupt:
            print("\n⏹️  تم إيقاف المثال بواسطة المستخدم")
        except Exception as e:
            print(f"❌ خطأ في {name}: {e}")
    
    else:
        print("❌ اختيار غير صحيح")

if __name__ == "__main__":
    main()
