#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
قواعد الأمان المخصصة لكشف الثغرات في تطبيقات Android
Custom Security Rules for Android Vulnerability Detection
"""

import re
from typing import List, Dict, Any

class SecurityRules:
    """فئة قواعد الأمان المخصصة"""
    
    def __init__(self):
        self.rules = self._load_rules()
    
    def _load_rules(self) -> Dict[str, Any]:
        """تحميل قواعد الأمان"""
        return {
            'payment_bypass': {
                'name': 'Payment Bypass Vulnerabilities',
                'description': 'كشف نقاط ضعف في أنظمة الدفع',
                'patterns': [
                    r'isPremium\s*=\s*true',
                    r'hasPaid\s*=\s*true',
                    r'paymentVerified\s*=\s*false',
                    r'SharedPreferences.*premium',
                    r'BuildConfig\.DEBUG.*payment',
                    r'if\s*\(\s*true\s*\).*premium',
                    r'bypass.*payment',
                    r'fake.*purchase'
                ],
                'severity': 'عالي',
                'cwe': 'CWE-840'
            },
            
            'authentication_bypass': {
                'name': 'Authentication Bypass',
                'description': 'تجاوز أنظمة المصادقة',
                'patterns': [
                    r'isLoggedIn\s*=\s*true',
                    r'authenticated\s*=\s*true',
                    r'if\s*\(\s*true\s*\).*login',
                    r'bypass.*auth',
                    r'skip.*login',
                    r'admin.*true',
                    r'root.*access',
                    r'developer.*mode'
                ],
                'severity': 'عالي',
                'cwe': 'CWE-287'
            },
            
            'api_vulnerabilities': {
                'name': 'API Security Issues',
                'description': 'مشاكل أمان في APIs',
                'patterns': [
                    r'http://.*api',  # HTTP غير آمن
                    r'api[_-]?key.*=.*["\'][^"\']{10,}["\']',  # API keys مكشوفة
                    r'secret.*=.*["\'][^"\']{10,}["\']',
                    r'password.*=.*["\'][^"\']{5,}["\']',
                    r'token.*=.*["\'][^"\']{10,}["\']',
                    r'\.execute\(\).*without.*validation',
                    r'HttpURLConnection.*setDoOutput\(true\)',
                    r'trust.*all.*certificates'
                ],
                'severity': 'متوسط',
                'cwe': 'CWE-319'
            },
            
            'data_leakage': {
                'name': 'Data Leakage Risks',
                'description': 'مخاطر تسريب البيانات',
                'patterns': [
                    r'Log\.[dve]\(',  # Logging sensitive data
                    r'System\.out\.print',
                    r'printStackTrace\(\)',
                    r'SharedPreferences.*MODE_WORLD_READABLE',
                    r'openFileOutput.*MODE_WORLD_READABLE',
                    r'getExternalStorage',
                    r'Environment\.getExternalStorageDirectory',
                    r'contact.*export',
                    r'sms.*export'
                ],
                'severity': 'متوسط',
                'cwe': 'CWE-200'
            },
            
            'modding_vulnerabilities': {
                'name': 'Modding Vulnerabilities',
                'description': 'نقاط ضعف تتيح التعديل',
                'patterns': [
                    r'BuildConfig\.DEBUG',
                    r'debuggable.*true',
                    r'allowBackup.*true',
                    r'exported.*true',
                    r'android:protectionLevel.*normal',
                    r'reflection.*getDeclaredMethod',
                    r'Class\.forName',
                    r'DexClassLoader',
                    r'PathClassLoader',
                    r'signature.*check.*false'
                ],
                'severity': 'متوسط',
                'cwe': 'CWE-489'
            },
            
            'rce_vulnerabilities': {
                'name': 'Remote Code Execution',
                'description': 'نقاط تنفيذ الأكواد عن بعد',
                'patterns': [
                    r'Runtime\.getRuntime\(\)\.exec',
                    r'ProcessBuilder',
                    r'eval\(',
                    r'javascript:.*eval',
                    r'loadUrl.*javascript:',
                    r'addJavascriptInterface',
                    r'setJavaScriptEnabled\(true\)',
                    r'WebView.*loadData',
                    r'Intent.*setData.*file://',
                    r'System\.load\(',
                    r'System\.loadLibrary\('
                ],
                'severity': 'عالي جداً',
                'cwe': 'CWE-94'
            },
            
            'crypto_weaknesses': {
                'name': 'Cryptographic Weaknesses',
                'description': 'نقاط ضعف في التشفير',
                'patterns': [
                    r'DES[^3]',  # DES ضعيف
                    r'MD5',      # MD5 ضعيف
                    r'SHA1',     # SHA1 ضعيف
                    r'ECB',      # ECB mode ضعيف
                    r'Random\(\)',  # Random ضعيف
                    r'Math\.random',
                    r'hardcoded.*key',
                    r'static.*final.*String.*key',
                    r'AES.*ECB',
                    r'cipher.*null'
                ],
                'severity': 'عالي',
                'cwe': 'CWE-327'
            },
            
            'network_security': {
                'name': 'Network Security Issues',
                'description': 'مشاكل أمان الشبكة',
                'patterns': [
                    r'TrustAllCertificates',
                    r'HostnameVerifier.*ALLOW_ALL',
                    r'checkServerTrusted.*return',
                    r'SSLContext.*TLS',
                    r'HttpURLConnection.*setHostnameVerifier',
                    r'HTTPS.*ignore.*certificate',
                    r'SSL.*disable.*verification',
                    r'certificate.*pinning.*disabled'
                ],
                'severity': 'عالي',
                'cwe': 'CWE-295'
            },
            
            'privilege_escalation': {
                'name': 'Privilege Escalation',
                'description': 'تصعيد الصلاحيات',
                'patterns': [
                    r'su\s+',
                    r'chmod\s+777',
                    r'setuid',
                    r'setgid',
                    r'root.*access',
                    r'superuser',
                    r'/system/bin/su',
                    r'busybox',
                    r'which.*su',
                    r'Superuser\.apk'
                ],
                'severity': 'عالي',
                'cwe': 'CWE-250'
            },
            
            'intent_vulnerabilities': {
                'name': 'Intent Security Issues',
                'description': 'مشاكل أمان Intent',
                'patterns': [
                    r'Intent.*setData.*content://',
                    r'Intent.*FLAG_GRANT_READ_URI_PERMISSION',
                    r'Intent.*FLAG_GRANT_WRITE_URI_PERMISSION',
                    r'exported.*true.*intent',
                    r'intent.*filter.*priority',
                    r'implicit.*intent.*sensitive',
                    r'PendingIntent.*FLAG_MUTABLE'
                ],
                'severity': 'متوسط',
                'cwe': 'CWE-926'
            }
        }
    
    def analyze_code(self, code_content: str, file_path: str = "") -> List[Dict[str, Any]]:
        """تحليل الكود للبحث عن الثغرات"""
        findings = []
        
        for rule_id, rule in self.rules.items():
            for pattern in rule['patterns']:
                matches = re.finditer(pattern, code_content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_number = code_content[:match.start()].count('\n') + 1
                    
                    finding = {
                        'rule_id': rule_id,
                        'rule_name': rule['name'],
                        'description': rule['description'],
                        'severity': rule['severity'],
                        'cwe': rule['cwe'],
                        'file_path': file_path,
                        'line_number': line_number,
                        'matched_text': match.group(),
                        'pattern': pattern,
                        'context': self._get_context(code_content, match.start(), match.end())
                    }
                    
                    findings.append(finding)
        
        return findings
    
    def _get_context(self, content: str, start: int, end: int, context_lines: int = 2) -> str:
        """الحصول على السياق حول المطابقة"""
        lines = content.split('\n')
        match_line = content[:start].count('\n')
        
        start_line = max(0, match_line - context_lines)
        end_line = min(len(lines), match_line + context_lines + 1)
        
        context_lines_list = []
        for i in range(start_line, end_line):
            prefix = ">>> " if i == match_line else "    "
            context_lines_list.append(f"{prefix}{i+1}: {lines[i]}")
        
        return '\n'.join(context_lines_list)
    
    def get_rule_categories(self) -> List[str]:
        """الحصول على فئات القواعد"""
        return list(self.rules.keys())
    
    def get_severity_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """إحصائيات الخطورة"""
        stats = {'عالي جداً': 0, 'عالي': 0, 'متوسط': 0, 'منخفض': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'منخفض')
            if severity in stats:
                stats[severity] += 1
        
        return stats

class YaraRules:
    """قواعد YARA لكشف البرمجيات الخبيثة"""
    
    @staticmethod
    def get_android_malware_rules() -> str:
        """قواعد YARA لكشف البرمجيات الخبيثة في Android"""
        return """
rule Android_Trojan_Generic {
    meta:
        description = "Generic Android Trojan Detection"
        author = "Security Research Team"
        date = "2024-01-01"
        
    strings:
        $a1 = "android.permission.SEND_SMS"
        $a2 = "android.permission.READ_SMS"
        $a3 = "android.permission.RECEIVE_SMS"
        $a4 = "SmsManager"
        $a5 = "sendTextMessage"
        
        $b1 = "TelephonyManager"
        $b2 = "getDeviceId"
        $b3 = "getSubscriberId"
        
        $c1 = "android.permission.ACCESS_FINE_LOCATION"
        $c2 = "LocationManager"
        $c3 = "getLastKnownLocation"
        
    condition:
        ($a1 and $a2 and $a4) or
        ($b1 and $b2 and $b3) or
        ($c1 and $c2 and $c3)
}

rule Android_Banking_Trojan {
    meta:
        description = "Android Banking Trojan Detection"
        
    strings:
        $bank1 = "bank" nocase
        $bank2 = "credit" nocase
        $bank3 = "paypal" nocase
        $bank4 = "wallet" nocase
        
        $overlay1 = "TYPE_SYSTEM_OVERLAY"
        $overlay2 = "TYPE_SYSTEM_ALERT"
        $overlay3 = "SYSTEM_ALERT_WINDOW"
        
        $admin1 = "DeviceAdminReceiver"
        $admin2 = "BIND_DEVICE_ADMIN"
        
    condition:
        any of ($bank*) and any of ($overlay*) and any of ($admin*)
}

rule Android_Spyware {
    meta:
        description = "Android Spyware Detection"
        
    strings:
        $spy1 = "record" nocase
        $spy2 = "monitor" nocase
        $spy3 = "track" nocase
        $spy4 = "keylog" nocase
        
        $perm1 = "RECORD_AUDIO"
        $perm2 = "CAMERA"
        $perm3 = "READ_CONTACTS"
        $perm4 = "READ_CALL_LOG"
        
    condition:
        any of ($spy*) and 2 of ($perm*)
}

rule Android_Adware {
    meta:
        description = "Android Adware Detection"
        
    strings:
        $ad1 = "admob" nocase
        $ad2 = "advertisement" nocase
        $ad3 = "banner" nocase
        $ad4 = "popup" nocase
        
        $aggressive1 = "TYPE_SYSTEM_OVERLAY"
        $aggressive2 = "setSystemUiVisibility"
        $aggressive3 = "HIDE_NAVIGATION"
        
    condition:
        2 of ($ad*) and any of ($aggressive*)
}
        """

class AndroidSecurityChecker:
    """فاحص أمان Android متقدم"""
    
    def __init__(self):
        self.security_rules = SecurityRules()
        self.yara_rules = YaraRules()
    
    def check_manifest_security(self, manifest_content: str) -> List[Dict[str, Any]]:
        """فحص أمان AndroidManifest.xml"""
        issues = []
        
        # فحص debuggable
        if 'android:debuggable="true"' in manifest_content:
            issues.append({
                'type': 'Debug Mode Enabled',
                'severity': 'متوسط',
                'description': 'وضع التصحيح مفعل في الإنتاج',
                'recommendation': 'تعطيل وضع التصحيح في النسخة النهائية'
            })
        
        # فحص allowBackup
        if 'android:allowBackup="true"' in manifest_content:
            issues.append({
                'type': 'Backup Allowed',
                'severity': 'منخفض',
                'description': 'النسخ الاحتياطي مسموح',
                'recommendation': 'تعطيل النسخ الاحتياطي للبيانات الحساسة'
            })
        
        # فحص exported components
        exported_pattern = r'android:exported="true"[^>]*>'
        exported_matches = re.findall(exported_pattern, manifest_content)
        if len(exported_matches) > 5:
            issues.append({
                'type': 'Many Exported Components',
                'severity': 'متوسط',
                'description': f'عدد كبير من المكونات المصدرة: {len(exported_matches)}',
                'recommendation': 'مراجعة ضرورة تصدير كل مكون'
            })
        
        return issues
    
    def analyze_network_security_config(self, config_content: str) -> List[Dict[str, Any]]:
        """تحليل إعدادات أمان الشبكة"""
        issues = []
        
        if 'cleartextTrafficPermitted="true"' in config_content:
            issues.append({
                'type': 'Cleartext Traffic Allowed',
                'severity': 'عالي',
                'description': 'الاتصالات غير المشفرة مسموحة',
                'recommendation': 'منع الاتصالات غير المشفرة'
            })
        
        if 'trustAnchors' not in config_content:
            issues.append({
                'type': 'No Certificate Pinning',
                'severity': 'متوسط',
                'description': 'لا يوجد تثبيت للشهادات',
                'recommendation': 'تطبيق تثبيت الشهادات'
            })
        
        return issues
