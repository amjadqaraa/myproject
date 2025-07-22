#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
محلل Frida للتحليل الديناميكي لتطبيقات Android
Frida Dynamic Analysis Module for Android Applications
"""

import json
import time
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path

class FridaAnalyzer:
    """فئة تحليل Frida الديناميكي"""
    
    def __init__(self, package_name: str):
        """
        تهيئة محلل Frida
        
        Args:
            package_name: اسم حزمة التطبيق
        """
        self.package_name = package_name
        self.device_id = None
        self.analysis_results = {}
        
    def check_frida_setup(self) -> bool:
        """التحقق من إعداد Frida"""
        try:
            # التحقق من وجود Frida
            result = subprocess.run(['frida', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print("خطأ: Frida غير مثبت")
                return False
            
            # التحقق من الأجهزة المتصلة
            result = subprocess.run(['frida-ls-devices'], 
                                  capture_output=True, text=True)
            if 'usb' not in result.stdout and 'emulator' not in result.stdout:
                print("تحذير: لا يوجد جهاز Android متصل")
                return False
            
            return True
            
        except FileNotFoundError:
            print("خطأ: Frida غير موجود في PATH")
            return False
    
    def get_frida_scripts(self) -> Dict[str, str]:
        """الحصول على سكريبتات Frida للتحليل"""
        scripts = {
            'ssl_pinning_bypass': '''
// تجاوز SSL Pinning
Java.perform(function() {
    console.log("[+] SSL Pinning Bypass Started");
    
    // OkHttp3 Pinning Bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] SSL Pinning bypassed for: " + hostname);
            return;
        };
    } catch(e) {
        console.log("[-] OkHttp3 not found");
    }
    
    // TrustManager Bypass
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        
        var TrustManager = Java.registerClass({
            name: "com.example.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        var TrustManagers = [TrustManager.$new()];
        var SSLContextInstance = SSLContext.getInstance("TLS");
        SSLContextInstance.init(null, TrustManagers, null);
        
        console.log("[+] TrustManager bypassed");
    } catch(e) {
        console.log("[-] TrustManager bypass failed: " + e);
    }
});
            ''',
            
            'root_detection_bypass': '''
// تجاوز كشف Root
Java.perform(function() {
    console.log("[+] Root Detection Bypass Started");
    
    // Common Root Detection Methods
    var rootChecks = [
        "isDeviceRooted",
        "isRooted",
        "checkRoot",
        "detectRoot",
        "isJailbroken"
    ];
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                
                methods.forEach(function(method) {
                    var methodName = method.getName();
                    
                    rootChecks.forEach(function(check) {
                        if (methodName.toLowerCase().includes(check.toLowerCase())) {
                            console.log("[+] Found root check: " + className + "." + methodName);
                            
                            try {
                                clazz[methodName].implementation = function() {
                                    console.log("[+] Bypassed: " + className + "." + methodName);
                                    return false;
                                };
                            } catch(e) {
                                console.log("[-] Failed to bypass: " + e);
                            }
                        }
                    });
                });
            } catch(e) {}
        },
        onComplete: function() {}
    });
    
    // File-based Root Detection
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getPath();
        var rootPaths = ["/system/bin/su", "/system/xbin/su", "/sbin/su", 
                        "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon"];
        
        if (rootPaths.includes(path)) {
            console.log("[+] Blocked root file check: " + path);
            return false;
        }
        
        return this.exists();
    };
});
            ''',
            
            'crypto_monitor': '''
// مراقبة العمليات التشفيرية
Java.perform(function() {
    console.log("[+] Crypto Monitor Started");
    
    // Monitor AES
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            console.log("[CRYPTO] Cipher.getInstance: " + transformation);
            return this.getInstance(transformation);
        };
        
        Cipher.doFinal.overload('[B').implementation = function(input) {
            console.log("[CRYPTO] Cipher.doFinal called with " + input.length + " bytes");
            return this.doFinal(input);
        };
    } catch(e) {
        console.log("[-] Cipher monitoring failed: " + e);
    }
    
    // Monitor Key Generation
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.generateKey.implementation = function() {
            console.log("[CRYPTO] Key generated with algorithm: " + this.getAlgorithm());
            return this.generateKey();
        };
    } catch(e) {
        console.log("[-] KeyGenerator monitoring failed: " + e);
    }
    
    // Monitor MessageDigest
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.digest.overload('[B').implementation = function(input) {
            console.log("[CRYPTO] MessageDigest.digest: " + this.getAlgorithm() + 
                       " with " + input.length + " bytes");
            return this.digest(input);
        };
    } catch(e) {
        console.log("[-] MessageDigest monitoring failed: " + e);
    }
});
            ''',
            
            'network_monitor': '''
// مراقبة الاتصالات الشبكية
Java.perform(function() {
    console.log("[+] Network Monitor Started");
    
    // Monitor HTTP Connections
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.implementation = function() {
            console.log("[NETWORK] HTTP Connection to: " + this.toString());
            return this.openConnection();
        };
        
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.getResponseCode.implementation = function() {
            var responseCode = this.getResponseCode();
            console.log("[NETWORK] Response Code: " + responseCode + " for " + this.getURL());
            return responseCode;
        };
    } catch(e) {
        console.log("[-] HTTP monitoring failed: " + e);
    }
    
    // Monitor OkHttp
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");
        
        OkHttpClient.newCall.implementation = function(request) {
            console.log("[NETWORK] OkHttp request to: " + request.url());
            return this.newCall(request);
        };
    } catch(e) {
        console.log("[-] OkHttp monitoring failed: " + e);
    }
    
    // Monitor Socket Connections
    try {
        var Socket = Java.use("java.net.Socket");
        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            console.log("[NETWORK] Socket connection to: " + host + ":" + port);
            return this.$init(host, port);
        };
    } catch(e) {
        console.log("[-] Socket monitoring failed: " + e);
    }
});
            ''',
            
            'payment_monitor': '''
// مراقبة عمليات الدفع
Java.perform(function() {
    console.log("[+] Payment Monitor Started");
    
    // Monitor Google Play Billing
    try {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.includes("billing") || className.includes("purchase") || 
                    className.includes("payment")) {
                    
                    console.log("[PAYMENT] Found payment class: " + className);
                    
                    try {
                        var clazz = Java.use(className);
                        var methods = clazz.class.getDeclaredMethods();
                        
                        methods.forEach(function(method) {
                            var methodName = method.getName();
                            
                            if (methodName.includes("purchase") || methodName.includes("buy") ||
                                methodName.includes("payment") || methodName.includes("verify")) {
                                
                                console.log("[PAYMENT] Found payment method: " + className + "." + methodName);
                                
                                try {
                                    clazz[methodName].implementation = function() {
                                        console.log("[PAYMENT] Called: " + className + "." + methodName);
                                        console.log("[PAYMENT] Arguments: " + JSON.stringify(arguments));
                                        
                                        var result = this[methodName].apply(this, arguments);
                                        console.log("[PAYMENT] Result: " + result);
                                        
                                        return result;
                                    };
                                } catch(e) {
                                    console.log("[-] Failed to hook: " + e);
                                }
                            }
                        });
                    } catch(e) {}
                }
            },
            onComplete: function() {}
        });
    } catch(e) {
        console.log("[-] Payment monitoring failed: " + e);
    }
    
    // Monitor SharedPreferences for payment flags
    try {
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        var Editor = Java.use("android.content.SharedPreferences$Editor");
        
        Editor.putBoolean.implementation = function(key, value) {
            if (key.toLowerCase().includes("premium") || key.toLowerCase().includes("paid") ||
                key.toLowerCase().includes("purchase")) {
                console.log("[PAYMENT] SharedPreferences putBoolean: " + key + " = " + value);
            }
            return this.putBoolean(key, value);
        };
        
        SharedPreferences.getBoolean.implementation = function(key, defValue) {
            var result = this.getBoolean(key, defValue);
            if (key.toLowerCase().includes("premium") || key.toLowerCase().includes("paid") ||
                key.toLowerCase().includes("purchase")) {
                console.log("[PAYMENT] SharedPreferences getBoolean: " + key + " = " + result);
            }
            return result;
        };
    } catch(e) {
        console.log("[-] SharedPreferences monitoring failed: " + e);
    }
});
            '''
        }
        
        return scripts
    
    def run_dynamic_analysis(self, analysis_duration: int = 60) -> Dict[str, Any]:
        """تشغيل التحليل الديناميكي"""
        if not self.check_frida_setup():
            return {'error': 'Frida setup failed'}
        
        results = {
            'ssl_pinning': [],
            'root_detection': [],
            'crypto_operations': [],
            'network_activity': [],
            'payment_activity': []
        }
        
        scripts = self.get_frida_scripts()
        
        try:
            # تشغيل كل سكريبت
            for script_name, script_code in scripts.items():
                print(f"تشغيل سكريبت: {script_name}")
                
                # حفظ السكريبت في ملف مؤقت
                script_file = f"/tmp/{script_name}.js"
                with open(script_file, 'w') as f:
                    f.write(script_code)
                
                # تشغيل Frida
                cmd = [
                    'frida',
                    '-U',  # USB device
                    '-f', self.package_name,  # Spawn app
                    '-l', script_file,  # Load script
                    '--no-pause'
                ]
                
                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # انتظار لمدة محددة
                    time.sleep(10)
                    process.terminate()
                    
                    stdout, stderr = process.communicate(timeout=5)
                    
                    # تحليل المخرجات
                    if stdout:
                        results[script_name.split('_')[0]] = self.parse_frida_output(stdout)
                    
                except subprocess.TimeoutExpired:
                    process.kill()
                except Exception as e:
                    print(f"خطأ في تشغيل {script_name}: {e}")
                
                # تنظيف الملف المؤقت
                Path(script_file).unlink(missing_ok=True)
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def parse_frida_output(self, output: str) -> List[Dict[str, Any]]:
        """تحليل مخرجات Frida"""
        findings = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or not line.startswith('['):
                continue
            
            try:
                # استخراج نوع الرسالة والمحتوى
                if '[+]' in line:
                    finding_type = 'success'
                elif '[-]' in line:
                    finding_type = 'error'
                elif '[CRYPTO]' in line:
                    finding_type = 'crypto'
                elif '[NETWORK]' in line:
                    finding_type = 'network'
                elif '[PAYMENT]' in line:
                    finding_type = 'payment'
                else:
                    finding_type = 'info'
                
                # استخراج المحتوى
                content = line.split(']', 1)[1].strip() if ']' in line else line
                
                findings.append({
                    'type': finding_type,
                    'message': content,
                    'timestamp': time.time()
                })
                
            except Exception:
                continue
        
        return findings
    
    def generate_dynamic_report(self, results: Dict[str, Any]) -> str:
        """إنشاء تقرير التحليل الديناميكي"""
        report = f"""
# تقرير التحليل الديناميكي - Dynamic Analysis Report
## التطبيق: {self.package_name}
## التاريخ: {time.strftime('%Y-%m-%d %H:%M:%S')}

---

### نتائج تجاوز SSL Pinning
"""
        
        if 'ssl' in results:
            for finding in results['ssl']:
                report += f"- {finding['message']}\n"
        
        report += "\n### نتائج كشف Root Detection\n"
        if 'root' in results:
            for finding in results['root']:
                report += f"- {finding['message']}\n"
        
        report += "\n### العمليات التشفيرية المكتشفة\n"
        if 'crypto' in results:
            for finding in results['crypto']:
                report += f"- {finding['message']}\n"
        
        report += "\n### النشاط الشبكي\n"
        if 'network' in results:
            for finding in results['network']:
                report += f"- {finding['message']}\n"
        
        report += "\n### نشاط الدفع\n"
        if 'payment' in results:
            for finding in results['payment']:
                report += f"- {finding['message']}\n"
        
        report += """
---

### ملاحظات:
- هذا التحليل يتطلب جهاز مع صلاحيات Root أو محاكي
- النتائج تعتمد على سلوك التطبيق أثناء التشغيل
- قد تحتاج لتفاعل يدوي مع التطبيق للحصول على نتائج أفضل
        """
        
        return report

def main():
    """دالة الاختبار"""
    import sys
    
    if len(sys.argv) < 2:
        print("الاستخدام: python frida_analyzer.py <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    analyzer = FridaAnalyzer(package_name)
    
    print(f"بدء التحليل الديناميكي للتطبيق: {package_name}")
    results = analyzer.run_dynamic_analysis()
    
    if 'error' in results:
        print(f"خطأ: {results['error']}")
        sys.exit(1)
    
    # إنشاء التقرير
    report = analyzer.generate_dynamic_report(results)
    
    # حفظ التقرير
    report_file = f"dynamic_analysis_{package_name}_{int(time.time())}.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"تم حفظ التقرير في: {report_file}")

if __name__ == "__main__":
    main()
