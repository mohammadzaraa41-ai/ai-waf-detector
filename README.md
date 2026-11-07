# SentinelWAF v3.0 — AI-Powered Web Vulnerability Discovery, Smart WAF & SAST Platform
# نظام اكتشاف ثغرات وهجمات الويب بالذكاء الاصطناعي (مشروع تخرج متكامل)

منصة أمنية متكاملة ثنائية اللغة (**English / العربية**) تجمع بين **3 محركات ذكاء اصطناعي وفحص أمني** تحت مظلة واحدة، وجاهزة للنشر السحابي المباشر على **Vercel**:
1. **محرك جدار حماية تطبيقات الويب بالذكاء الاصطناعي (Real-ML HTTP Request WAF):** يفحص طلبات `HTTP/HTTPS` عبر فك التشفير الثلاثي (`3x Recursive URL Decoding`) ومقاطع الأحرف `Character N-Grams (2..5)` مع `StandardScaler` والشبكة العصبية العميقة `Deep MLP (128, 64)`، بالإضافة إلى تصدير الأوزان الرياضية الفعلية إلى [`api/model_weights.json`](api/model_weights.json) للعمل على السحابة (`W · x + b -> Softmax`) بزمن استجابة أقل من `3 ms`.
2. **فاحص ثغرات المواقع ونماذج الإدخال بالرابط (Deep URL, Header & HTML Form Scanner):** يحلل ترويسات الأمان (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`)، إعدادات الكوكيز (`HttpOnly`)، ويستخرج جميع نماذج `<form>` وحقول `<input>` لاكتشاف ثغرات `CSRF` و `DOM XSS Sinks` وحقن معاملات الرابط.
3. **فاحص الكود المصدري بالذكاء الاصطناعي (AI Static Source Code Scanner - SAST):** يحلل أكواد `Python`, `PHP`, و `Node.js` سطراً بسطر لاكتشاف ثغرات `SQL Injection (CWE-89)`, `XSS (CWE-79)`, `OS Command Injection (CWE-78)`, `Dynamic Eval (CWE-94)`, `Path Traversal / LFI (CWE-22)`, و `Hardcoded Secrets (CWE-798)` مع توليد الكود الآمن البديل (`Automated Secure Patch`).

---

## هيكل المشروع (Project Structure)

```text
ai-waf-detector/
├── index.html                 # واجهة المنصة السحابية (SENTINEL-WAF v3.0 Console — EN/AR)
├── vercel.json                # إعدادات النشر السحابي على Vercel
├── api/
│   ├── scan.py                # نقطة النهاية السحابية (Real ML Weights + URL Form Audit + SAST)
│   └── model_weights.json     # أوزان النموذج المدرب المصدرة للسحابة (16.8 KB)
├── data/
│   └── http_requests.csv      # قاعدة البيانات الموسعة (1,543 عينة فريدة تشمل Hard Negatives و Zero-Day)
├── logs/
│   └── waf_events.csv         # سجل الأحداث الأمنية الحية لجدار الحماية (SIEM Telemetry)
├── models/
│   └── waf_model.joblib       # النموذج المحلي الكامل (Deep MLP + TF-IDF + StandardScaler)
├── docs/                      # تقارير التخرج (5 ملفات Word + عرض PowerPoint باللغتين)
├── src/
│   ├── preprocess.py          # فك التشفير الثلاثي واستخراج الخصائص الإحصائية والسياقية
│   ├── dataset_builder.py     # بناء وتوليد قاعدة البيانات الموسعة (1,543 طلب)
│   ├── train.py               # تدريب ومقارنة النماذج وتصدير الأوزان السحابية ومصفوفة الالتباس
│   ├── waf_engine.py          # محرك الفحص اللحظي وتسجيل الأحداث الأمنية
│   ├── waf_server.py          # خادم FastAPI مزود بـ AI WAF Middleware (200 OK vs 403 Forbidden)
│   ├── url_scanner.py         # فاحص المواقع والترويسات ونماذج HTML بالرابط
│   ├── code_scanner.py        # محرك فحص الكود المصدري بالذكاء الاصطناعي (SAST Engine)
│   ├── test_waf_live.py       # اختبار محاكاة حي لجدار الحماية على 9 سيناريوهات
│   ├── test_v3_upgrade.py     # اختبار التحقق من الأوزان السحابية ومحرك SAST وسلامة الواجهة
│   └── app.py                 # لوحة تحكم تفاعلية بـ 5 تبويبات (Streamlit Dashboard)
└── requirements-local.txt     # المكتبات المطلوبة للتشغيل المحلي
```

---

## ملخص نتائج تقييم النماذج (Evaluation Metrics on Holdout + Zero-Day Split, N = 394)

| النموذج (Model Architecture) | Accuracy | Macro Precision | Macro Recall | Macro F1 | False Positive Rate (Normal) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Deep MLP Neural Network (128, 64)** | **0.9975** | **0.9973** | **0.9972** | **0.9972** | **0.00% (124/124)** |
| **Random Forest (100 Trees)** | 0.9975 | 0.9972 | 0.9980 | 0.9976 | 0.81% |
| **Logistic Regression (Baseline)** | 0.9898 | 0.9904 | 0.9896 | 0.9900 | 0.81% |

---

## طريقة التشغيل المحلي (Local Quick Start)

1. **تفعيل البيئة الافتراضية:**
   ```powershell
   .\.venv\Scripts\activate
   ```
2. **إعادة توليد البيانات وتدريب النماذج وتصدير الأوزان السحابية:**
   ```powershell
   python src/train.py
   ```
3. **تشغيل اختبارات التحقق الشاملة (WAF + Cloud Weights + SAST):**
   ```powershell
   python src/test_waf_live.py
   python src/test_v3_upgrade.py
   ```
4. **تشغيل لوحة التحكم المحلية (Streamlit 5-Tab Console):**
   ```powershell
   streamlit run src/app.py
   ```
