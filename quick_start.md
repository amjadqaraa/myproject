# دليل البدء السريع - Quick Start Guide

## 🚀 التشغيل السريع

### 1. التثبيت التلقائي
```bash
chmod +x install.sh
./install.sh
```

### 2. اختبار التثبيت
```bash
python3 test_installation.py
```

### 3. تحليل ملف APK
```bash
# الطريقة الأولى
python3 apk_security_analyzer.py -f your_app.apk

# الطريقة الثانية (بعد التثبيت)
./analyze_apk.sh -f your_app.apk
```

### 4. تشغيل الأمثلة
```bash
python3 examples.py
```

## ⚡ أوامر سريعة

### تحليل أساسي
```bash
python3 apk_security_analyzer.py -f app.apk
```

### تحليل مع مجلد مخرجات مخصص
```bash
python3 apk_security_analyzer.py -f app.apk -o my_analysis
```

### تحليل مفصل
```bash
python3 apk_security_analyzer.py -f app.apk --verbose
```

### تحليل ديناميكي (يتطلب جهاز Android)
```bash
python3 frida_analyzer.py com.example.app
```

## 📋 قائمة فحص سريعة

- [ ] Python 3.8+ مثبت
- [ ] المكتبات مثبتة (`pip install -r requirements.txt`)
- [ ] ملف APK للاختبار موجود
- [ ] قراءة التحذير القانوني ✅
- [ ] تشغيل اختبار التثبيت

## 🆘 حل المشاكل السريع

### مشكلة: "مكتبة غير مثبتة"
```bash
pip3 install -r requirements.txt
```

### مشكلة: "apktool غير موجود"
```bash
sudo apt-get install apktool
# أو
./install.sh
```

### مشكلة: "صلاحيات"
```bash
chmod +x *.py *.sh
```

## 📞 الدعم

1. راجع `README.md` للتفاصيل الكاملة
2. شغل `python3 test_installation.py` للتشخيص
3. تأكد من قراءة `LICENSE` للاستخدام القانوني

---

⚠️ **تذكر**: هذه الأداة للاستخدام الشرعي فقط!
