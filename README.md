# نظام ذكي لاكتشاف هجمات وثغرات الويب عبر تحليل طلبات HTTP (AI-Based Web Request Analyzer & Smart WAF)

مشروع تخرج متكامل يقوم بتحليل طلبات الويب (`HTTP Requests`) في الوقت الفعلي واكتشاف الهجمات الشائعة (`SQL Injection`, `XSS`, `Path Traversal`, `Command Injection`) باستخدام دمج الخصائص الإحصائية السياقية مع `Character N-Grams` والشبكات العصبية (`Deep MLP`).

## هيكل المشروع (Project Structure)

```text
ai-waf-detector/
├── data/
│   └── http_requests.csv      # قاعدة البيانات الموسعة (979 عينة فريدة تشمل Hard Negatives)
├── logs/
│   └── waf_events.csv         # سجل الأحداث الأمنية الحية لجدار الحماية (SOC Logs)
├── models/
│   └── waf_model.joblib       # النموذج المدرب (Deep MLP + TF-IDF + StandardScaler)
├── src/
│   ├── preprocess.py          # فك التشفير المزدوج واستخراج الخصائص السياقية والإحصائية
│   ├── dataset_builder.py     # بناء وتوليد قاعدة البيانات الموسعة
│   ├── train.py               # تدريب ومقارنة 3 نماذج ذكاء اصطناعي وتوليد جداول التقييم
│   ├── waf_engine.py          # محرك الفحص اللحظي وتسجيل الأحداث الأمنية
│   ├── waf_server.py          # خادم FastAPI مزود بـ AI WAF Middleware لحجب الهجمات بـ 403
│   ├── test_waf_live.py       # اختبار محاكاة حي لجدار الحماية على 9 سيناريوهات واقعية
│   └── app.py                 # لوحة تحكم تفاعلية (Streamlit SOC & XAI Dashboard)
├── requirements.txt           # المكتبات المطلوبة
└── README.md                  # توثيق المشروع
```

## طريقة التشغيل (Quick Start)

1. **تفعيل البيئة الافتراضية الجاهزة:**
   ```powershell
   cd C:\Users\lenovo\.gemini\antigravity\scratch\ai-waf-detector
   .\.venv\Scripts\activate
   ```

2. **توليد البيانات وتدريب ومقارنة النماذج:**
   ```powershell
   python src/train.py
   ```

3. **تشغيل اختبار محاكاة جدار الحماية الحي (Live WAF Middleware Test):**
   ```powershell
   python src/test_waf_live.py
   ```

4. **تشغيل خادم الويب المحمي بـ AI WAF (اختياري للتجربة عبر المتصفح على المنفذ 8000):**
   ```powershell
   uvicorn src.waf_server:app --reload --port 8000
   ```

5. **تشغيل لوحة التحكم ومراقبة الأحداث (Streamlit Dashboard):**
   ```powershell
   pip install streamlit
   streamlit run src/app.py
   ```
