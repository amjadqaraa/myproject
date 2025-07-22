#!/bin/bash
# سكريبت التثبيت التلقائي لأداة تحليل أمان APK
# Automatic Installation Script for APK Security Analysis Tool

set -e

# الألوان للمخرجات
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# دالة طباعة ملونة
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# التحقق من المتطلبات الأساسية
check_requirements() {
    print_status "التحقق من المتطلبات الأساسية..."
    
    # التحقق من Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 غير مثبت"
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ $(echo "$python_version < 3.8" | bc) -eq 1 ]]; then
        print_error "Python 3.8+ مطلوب، الإصدار الحالي: $python_version"
        exit 1
    fi
    
    print_success "Python $python_version موجود"
    
    # التحقق من pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 غير مثبت"
        exit 1
    fi
    
    print_success "pip3 موجود"
    
    # التحقق من Java (اختياري)
    if command -v java &> /dev/null; then
        java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
        print_success "Java $java_version موجود"
    else
        print_warning "Java غير موجود - بعض الميزات قد لا تعمل"
    fi
}

# تثبيت أدوات النظام
install_system_tools() {
    print_status "تثبيت أدوات النظام..."
    
    # تحديث قوائم الحزم
    if command -v apt-get &> /dev/null; then
        print_status "تحديث قوائم الحزم..."
        sudo apt-get update -qq
        
        # تثبيت الأدوات الأساسية
        print_status "تثبيت الأدوات الأساسية..."
        sudo apt-get install -y \
            python3-pip \
            python3-dev \
            python3-venv \
            build-essential \
            libssl-dev \
            libffi-dev \
            libjpeg-dev \
            zlib1g-dev \
            wget \
            curl \
            unzip \
            default-jdk \
            android-tools-adb \
            bc
        
        # تثبيت apktool
        if ! command -v apktool &> /dev/null; then
            print_status "تثبيت apktool..."
            
            # تحميل apktool
            wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /tmp/apktool
            wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar -O /tmp/apktool.jar
            
            # تثبيت apktool
            sudo cp /tmp/apktool /usr/local/bin/
            sudo cp /tmp/apktool.jar /usr/local/bin/
            sudo chmod +x /usr/local/bin/apktool
            
            # تنظيف الملفات المؤقتة
            rm -f /tmp/apktool /tmp/apktool.jar
            
            print_success "تم تثبيت apktool"
        else
            print_success "apktool موجود مسبقاً"
        fi
        
    elif command -v yum &> /dev/null; then
        print_status "نظام Red Hat/CentOS مكتشف..."
        sudo yum update -y
        sudo yum install -y python3-pip python3-devel gcc openssl-devel libffi-devel java-1.8.0-openjdk
        
    else
        print_warning "مدير الحزم غير مدعوم، يرجى التثبيت اليدوي"
    fi
}

# إنشاء بيئة افتراضية
create_virtual_env() {
    print_status "إنشاء بيئة افتراضية..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "تم إنشاء البيئة الافتراضية"
    else
        print_success "البيئة الافتراضية موجودة"
    fi
    
    # تفعيل البيئة الافتراضية
    source venv/bin/activate
    
    # تحديث pip
    pip install --upgrade pip setuptools wheel
}

# تثبيت مكتبات Python
install_python_packages() {
    print_status "تثبيت مكتبات Python..."
    
    # تأكد من تفعيل البيئة الافتراضية
    if [[ "$VIRTUAL_ENV" == "" ]]; then
        source venv/bin/activate
    fi
    
    # تثبيت المكتبات الأساسية
    pip install -r requirements.txt
    
    # تثبيت مكتبات إضافية قد تكون مفيدة
    pip install \
        ipython \
        jupyter \
        pytest \
        black \
        flake8 \
        mypy
    
    print_success "تم تثبيت مكتبات Python"
}

# تثبيت Frida (اختياري)
install_frida() {
    print_status "تثبيت Frida للتحليل الديناميكي..."
    
    # تأكد من تفعيل البيئة الافتراضية
    if [[ "$VIRTUAL_ENV" == "" ]]; then
        source venv/bin/activate
    fi
    
    # تثبيت Frida
    pip install frida-tools
    
    # تحميل frida-server للأندرويد
    print_status "تحميل frida-server..."
    
    # إنشاء مجلد frida-server
    mkdir -p tools/frida-server
    
    # تحديد معمارية النظام
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            FRIDA_ARCH="x86_64"
            ;;
        aarch64|arm64)
            FRIDA_ARCH="arm64"
            ;;
        armv7l)
            FRIDA_ARCH="arm"
            ;;
        *)
            FRIDA_ARCH="x86_64"
            ;;
    esac
    
    # تحميل أحدث إصدار من frida-server
    FRIDA_VERSION=$(pip show frida | grep Version | cut -d' ' -f2)
    FRIDA_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}.xz"
    
    if wget -q "$FRIDA_URL" -O "tools/frida-server/frida-server-${FRIDA_ARCH}.xz"; then
        cd tools/frida-server
        xz -d "frida-server-${FRIDA_ARCH}.xz"
        mv "frida-server-${FRIDA_ARCH}" "frida-server"
        chmod +x frida-server
        cd ../..
        print_success "تم تحميل frida-server"
    else
        print_warning "فشل في تحميل frida-server - يمكن تحميله يدوياً لاحقاً"
    fi
}

# إعداد المجلدات
setup_directories() {
    print_status "إعداد المجلدات..."
    
    # إنشاء المجلدات المطلوبة
    mkdir -p analysis_output
    mkdir -p samples
    mkdir -p tools
    mkdir -p logs
    mkdir -p templates
    
    # إعطاء صلاحيات التنفيذ للسكريبتات
    chmod +x apk_security_analyzer.py
    chmod +x frida_analyzer.py
    
    print_success "تم إعداد المجلدات"
}

# إنشاء ملف التكوين
create_config() {
    print_status "إنشاء ملف التكوين..."
    
    cat > config.json << 'CONFIG_EOF'
{
    "analysis": {
        "max_file_size": 536870912,
        "timeout": 300,
        "temp_dir": "/tmp/apk_analysis",
        "output_formats": ["html", "json", "pdf"]
    },
    "security": {
        "enable_dynamic_analysis": false,
        "enable_network_analysis": true,
        "enable_crypto_analysis": true,
        "max_severity_score": 100
    },
    "tools": {
        "apktool_path": "/usr/local/bin/apktool",
        "frida_server_path": "./tools/frida-server/frida-server",
        "java_path": "/usr/bin/java"
    },
    "reporting": {
        "include_source_code": false,
        "include_screenshots": false,
        "language": "ar"
    }
}
CONFIG_EOF
    
    print_success "تم إنشاء ملف التكوين"
}

# اختبار التثبيت
test_installation() {
    print_status "اختبار التثبيت..."
    
    # تأكد من تفعيل البيئة الافتراضية
    if [[ "$VIRTUAL_ENV" == "" ]]; then
        source venv/bin/activate
    fi
    
    # اختبار استيراد المكتبات الأساسية
    python3 -c "
import sys
try:
    import androguard
    print('✓ androguard')
except ImportError as e:
    print('✗ androguard:', e)
    sys.exit(1)

try:
    import rich
    print('✓ rich')
except ImportError as e:
    print('✗ rich:', e)
    sys.exit(1)

try:
    import pandas
    print('✓ pandas')
except ImportError as e:
    print('✗ pandas:', e)
    sys.exit(1)

try:
    import reportlab
    print('✓ reportlab')
except ImportError as e:
    print('✗ reportlab:', e)
    sys.exit(1)

print('جميع المكتبات الأساسية متوفرة')
"
    
    # اختبار السكريبت الرئيسي
    if python3 apk_security_analyzer.py --help > /dev/null 2>&1; then
        print_success "السكريبت الرئيسي يعمل بشكل صحيح"
    else
        print_error "مشكلة في السكريبت الرئيسي"
        exit 1
    fi
    
    print_success "اختبار التثبيت مكتمل بنجاح!"
}

# إنشاء سكريبت التشغيل
create_launcher() {
    print_status "إنشاء سكريبت التشغيل..."
    
    cat > analyze_apk.sh << 'LAUNCHER_EOF'
#!/bin/bash
# سكريبت تشغيل سريع لأداة تحليل APK

# تفعيل البيئة الافتراضية
source venv/bin/activate

# تشغيل الأداة مع المعاملات المرسلة
python3 apk_security_analyzer.py "$@"
LAUNCHER_EOF
    
    chmod +x analyze_apk.sh
    
    print_success "تم إنشاء سكريبت التشغيل السريع: ./analyze_apk.sh"
}

# الدالة الرئيسية
main() {
    echo "=================================================="
    echo "أداة تحليل أمان APK - سكريبت التثبيت التلقائي"
    echo "APK Security Analysis Tool - Auto Installer"
    echo "=================================================="
    echo
    
    # التحقق من المتطلبات
    check_requirements
    
    # تثبيت أدوات النظام
    install_system_tools
    
    # إنشاء البيئة الافتراضية
    create_virtual_env
    
    # تثبيت مكتبات Python
    install_python_packages
    
    # تثبيت Frida (اختياري)
    read -p "هل تريد تثبيت Frida للتحليل الديناميكي؟ (y/N): " install_frida_choice
    if [[ $install_frida_choice =~ ^[Yy]$ ]]; then
        install_frida
    fi
    
    # إعداد المجلدات
    setup_directories
    
    # إنشاء ملف التكوين
    create_config
    
    # إنشاء سكريبت التشغيل
    create_launcher
    
    # اختبار التثبيت
    test_installation
    
    echo
    echo "=================================================="
    print_success "تم التثبيت بنجاح!"
    echo "=================================================="
    echo
    echo "لبدء الاستخدام:"
    echo "1. تفعيل البيئة الافتراضية: source venv/bin/activate"
    echo "2. تشغيل الأداة: python3 apk_security_analyzer.py -f app.apk"
    echo "أو استخدام السكريبت السريع: ./analyze_apk.sh -f app.apk"
    echo
    echo "للحصول على المساعدة:"
    echo "./analyze_apk.sh --help"
    echo
    echo "⚠️  تذكر: استخدم هذه الأداة لأغراض شرعية فقط!"
}

# تشغيل الدالة الرئيسية
main "$@"
