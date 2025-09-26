# 🏷️ خدمة الرسائل المبسطة (naebak-messaging-service)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/egyptofrance/naebak-messaging-service/actions)
[![Coverage](https://img.shields.io/badge/coverage-N/A-lightgrey)](https://github.com/egyptofrance/naebak-messaging-service)
[![Version](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com/egyptofrance/naebak-messaging-service/releases)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

## 🔄 **تحديث مهم - الإصدار 2.0.0**

تم تبسيط خدمة الرسائل بشكل كامل لتصبح أكثر استقراراً وسهولة في الصيانة. تم إزالة الميزات المعقدة التي كانت تسبب تعقيدات غير ضرورية.

### ❌ **الميزات المحذوفة (كانت تسبب تعقيد):**
- مشاركة الملفات والوسائط
- مؤشرات القراءة ("تم القراءة")
- مؤشرات الكتابة ("يكتب الآن...")
- التشفير المعقد للرسائل
- البحث في الرسائل
- WebSocket والاتصال الفوري
- Redis للتخزين المؤقت

### ✅ **الميزات المتاحة (بسيطة وموثوقة):**
- إرسال رسائل نصية بسيطة
- عرض المحادثات
- حذف الرسائل
- إحصائيات أساسية

---

## 📝 الوصف

خدمة رسائل بسيطة وموثوقة بين المواطنين والنواب. تركز على الوظائف الأساسية بدون تعقيدات تقنية.

---

## ✨ الميزات الرئيسية

- **رسائل نصية بسيطة**: إرسال واستقبال الرسائل النصية فقط
- **محادثات منظمة**: عرض المحادثات بين المواطن والنائب
- **حذف الرسائل**: إمكانية حذف الرسائل المرسلة
- **إحصائيات**: عدد المحادثات والرسائل

---

## 🛠️ التقنيات المستخدمة

| التقنية | الإصدار | الغرض |
|---------|---------|-------|
| **Flask** | 2.3.2 | إطار العمل الأساسي |
| **SQLite** | مدمج | قاعدة البيانات المحلية |
| **Flask-CORS** | 4.0.0 | دعم CORS |
| **Flask-JWT-Extended** | 4.5.2 | المصادقة |

---

## 🚀 التثبيت والتشغيل

### **المتطلبات الأساسية**

- Python 3.8+
- لا يحتاج قواعد بيانات خارجية
- لا يحتاج Redis أو خدمات إضافية

### **التثبيت المحلي**

```bash
git clone https://github.com/egyptofrance/naebak-messaging-service.git
cd naebak-messaging-service

# تثبيت المتطلبات (3 مكتبات فقط!)
pip install -r requirements.txt

# تشغيل الخدمة
python messaging_simple.py
```

الخدمة ستعمل على: `http://localhost:8002`

---

## 📚 توثيق الـ API

### **الـ Endpoints المتاحة:**

#### 1. فحص حالة الخدمة
```bash
GET /health
```

#### 2. جلب المحادثات
```bash
GET /api/conversations?user_type=citizen
```

#### 3. جلب رسائل محادثة معينة
```bash
GET /api/conversations/{conversation_id}/messages?page=1&per_page=50
```

#### 4. إرسال رسالة جديدة
```bash
POST /api/messages
{
  "recipient_id": "deputy_123",
  "content": "مرحبا، لدي استفسار",
  "sender_type": "citizen"
}
```

#### 5. حذف رسالة
```bash
DELETE /api/messages/{message_id}
```

#### 6. إحصائيات المستخدم
```bash
GET /api/stats?user_type=citizen
```

---

## 🗄️ قاعدة البيانات

تستخدم الخدمة **SQLite** كقاعدة بيانات محلية بسيطة:

### **الجداول:**

#### `conversations`
- `id`: معرف المحادثة
- `citizen_id`: معرف المواطن
- `deputy_id`: معرف النائب
- `created_at`: تاريخ الإنشاء
- `updated_at`: تاريخ آخر تحديث

#### `messages`
- `id`: معرف الرسالة
- `conversation_id`: معرف المحادثة
- `sender_id`: معرف المرسل
- `sender_type`: نوع المرسل (citizen/deputy)
- `content`: محتوى الرسالة (نص فقط)
- `created_at`: تاريخ الإرسال
- `deleted`: حالة الحذف

---

## 🔒 الأمان

- **JWT**: مصادقة آمنة للمستخدمين
- **HTTPS**: تشفير النقل (في الإنتاج)
- **التحقق من الصلاحيات**: كل مستخدم يرى رسائله فقط
- **Soft Delete**: الرسائل المحذوفة لا تُمحى نهائياً

---

## 📊 مقارنة الإصدارات

| الميزة | الإصدار 1.0 (المعقد) | الإصدار 2.0 (المبسط) |
|--------|-------------------|-------------------|
| **التبعيات** | 9+ مكتبات | 3 مكتبات |
| **قاعدة البيانات** | PostgreSQL + Redis | SQLite |
| **حجم الكود** | 1000+ سطر | 400 سطر |
| **الملفات** | 10+ ملفات | ملف واحد |
| **مشاركة الملفات** | ✅ | ❌ |
| **مؤشرات القراءة** | ✅ | ❌ |
| **WebSocket** | ✅ | ❌ |
| **البساطة** | ❌ | ✅ |
| **الاستقرار** | متوسط | عالي |

---

## 🧪 الاختبارات

```bash
# اختبار سريع للخدمة
curl http://localhost:8002/health

# النتيجة المتوقعة:
{
  "status": "healthy",
  "service": "simple-messaging",
  "version": "2.0.0",
  "features": {
    "file_upload": false,
    "read_receipts": false,
    "encryption": false,
    "search": false,
    "websocket": false,
    "simple_text_messaging": true
  }
}
```

---

## 🎯 فلسفة التبسيط

هذا الإصدار يتبع مبدأ **"البساطة أولاً"**:

- **80% من الفائدة بـ 20% من التعقيد**
- **سهولة الصيانة أهم من الميزات المتقدمة**
- **الاستقرار أولوية على الابتكار**
- **كود واضح أفضل من كود ذكي**

---

## 🤝 المساهمة

يرجى مراجعة [دليل المساهمة](CONTRIBUTING.md) و [معايير التوثيق الموحدة](../../naebak-almakhzan/DOCUMENTATION_STANDARDS.md).

---

## 📄 الترخيص

هذا المشروع مرخص تحت [رخصة MIT](LICENSE).

---

## 📞 الدعم

للأسئلة والدعم الفني، يرجى فتح [issue جديد](https://github.com/egyptofrance/naebak-messaging-service/issues).
