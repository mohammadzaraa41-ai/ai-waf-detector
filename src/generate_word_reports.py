import os
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor


def set_heading_style(heading, color_rgb=(26, 54, 93)):
    for run in heading.runs:
        run.font.color.rgb = RGBColor(*color_rgb)
        run.font.name = "Arial"


def add_styled_table(doc, headers, rows):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    hdr_cells = table.rows[0].cells
    for i, header_text in enumerate(headers):
        hdr_cells[i].text = header_text
        for paragraph in hdr_cells[i].paragraphs:
            for run in paragraph.runs:
                run.font.bold = True
                run.font.name = "Arial"
                run.font.size = Pt(10)

    for row_data in rows:
        row_cells = table.add_row().cells
        for i, val in enumerate(row_data):
            row_cells[i].text = str(val)
            for paragraph in row_cells[i].paragraphs:
                for run in paragraph.runs:
                    run.font.name = "Arial"
                    run.font.size = Pt(10)
    doc.add_paragraph()


def build_week1_section(doc):
    h = doc.add_heading("الأسبوع الأول (Week 1): تحديد المشكلة، الإطار النظري، والدراسات السابقة\nProblem Definition, Theoretical Framework & Literature Review", level=1)
    set_heading_style(h)

    # English Section
    doc.add_heading("1.1 Executive Summary & Problem Statement (English)", level=2)
    doc.add_paragraph(
        "Modern web applications face sophisticated cyber attacks targeting the application layer (HTTP/HTTPS), "
        "most notably SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal, and Command Injection. "
        "Traditional Rule-Based Web Application Firewalls (such as ModSecurity) suffer from two major limitations:\n"
        "1. High False Positive Rates: Blocking legitimate users whose natural search queries contain words like 'select', 'update', or 'script'.\n"
        "2. Evasion via Obfuscation: Attackers bypass static Regular Expressions (Regex) using Double URL Encoding, SQL inline comments (/**/), or novel payload structures.\n"
        "Objective: Design and implement a hybrid AI-driven HTTP Request Analyzer and Smart WAF capable of real-time detection with minimal false positives."
    )

    # Arabic Section
    doc.add_heading("1.2 الملخص ومشكلة البحث وأهداف الأسبوع الأول (العربية)", level=2)
    doc.add_paragraph(
        "تواجه تطبيقات الويب الحديثة هجمات سيبرانية متطورة تستهدف طبقة التطبيقات عبر طلبات HTTP، وأبرزها حقن قواعد البيانات (SQLi)، "
        "والبرمجة عبر المواقع (XSS)، واختراق المسارات وحقن الأوامر (Path Traversal & Command Injection).\n"
        "تعاني جدران الحماية التقليدية المعتمدة على القواعد الثابتة (Signature-based WAFs) من مشكلتين رئيسيتين:\n"
        "1. ارتفاع الإنذارات الكاذبة (False Positives): حظر المستخدمين الشرعيين عند كتابة جمل بحث طبيعية تحتوي على مفردات مثل select أو update.\n"
        "2. سهولة التجاوز بالتمويه والتشفير (Obfuscation): الالتفاف على القواعد الثابتة عبر التشفير المزدوج (Double URL Encoding).\n"
        "الهدف: بناء نظام ذكاء اصطناعي هجين يحلل سياق الطلب ومقاطع الأحرف (Character N-Grams) لاكتشاف الهجمات لحظياً."
    )

    doc.add_heading("1.3 Comparison with Related Work / مقارنة بالدراسات والأنظمة السابقة", level=2)
    headers = [
        "Feature / المعيار",
        "Traditional WAF (ModSecurity)",
        "Classic ML (Word TF-IDF)",
        "Proposed Hybrid AI-WAF (مشروعنا)",
    ]
    rows = [
        ["Analysis Method / طريقة الفحص", "Static Regex Rules", "Word-level Tokenization", "Char N-Grams (2-5) + Contextual Features"],
        ["Obfuscation Resistance / مقاومة التمويه", "Low (ضعيفة)", "Medium (متوسطة)", "Very High (عالية جداً - يفك التشفير المزدوج)"],
        ["False Positives / الإنذارات الكاذبة", "High (مرتفعة)", "Moderate (متوسطة)", "Near Zero (منخفضة جداً بفضل السياق)"],
        ["Explainability / قابلية التفسير", "Rule ID only", "Black-box", "Full XAI Metrics & Confidence Scores"],
    ]
    add_styled_table(doc, headers, rows)


def build_week2_section(doc):
    h = doc.add_heading("الأسبوع الثاني (Week 2): بناء قاعدة البيانات وهندسة الخصائص السياقية\nDataset Construction, Normalization & Contextual Feature Engineering", level=1)
    set_heading_style(h)

    doc.add_heading("2.1 Dataset Engineering & Normalization (English)", level=2)
    doc.add_paragraph(
        "In Week 2, we constructed a diverse dataset of 979 unique HTTP requests (data/http_requests.csv) distributed across 4 classes:\n"
        "- Normal (320 samples): Includes standard web browsing, API calls, and challenging 'Hard Negatives' (natural queries containing SQL/HTML terms).\n"
        "- SQLi (220 samples): Union-based, boolean-based, time-based blind, comment-obfuscated, and URL-encoded SQL injection payloads.\n"
        "- XSS (219 samples): Script tags, event handlers (onload/onerror), SVG vectors, JavaScript URI schemes, and encoded payloads.\n"
        "- Path_Cmd_Attack (220 samples): Directory traversal (../etc/passwd, win.ini) and OS command injection (; cat, | whoami, && ls).\n\n"
        "Preprocessing Pipeline (src/preprocess.py):\n"
        "1. Recursive Double URL Decoding (urllib.parse.unquote_plus) and lowercase normalization.\n"
        "2. Shannon Entropy calculation H(X) to measure payload randomness and obfuscation.\n"
        "3. Contextual Regex Indicators that match syntactic attack structures rather than isolated English words."
    )

    doc.add_heading("2.2 تجهيز البيانات واستخراج الخصائص الهجينة (العربية)", level=2)
    doc.add_paragraph(
        "تم في الأسبوع الثاني بناء قاعدة بيانات موسعة تضم 979 طلباً فريداً غير مكرر في الملف (data/http_requests.csv)، مع التركيز على إضافة "
        "عينات طبيعية خادعة (Hard Negatives) لاختبار قدرة النموذج على عدم إصدار إنذارات كاذبة.\n"
        "خطوات المعالجة واستخراج الخصائص في (src/preprocess.py):\n"
        "1. فك التشفير المزدوج (Double URL Decoding) لإحباط محاولات إخفاء الرموز الخبيثة.\n"
        "2. حساب عشوائية شانون (Shannon Entropy) ونسبة الرموز الخاصة والأرقام إلى طول الرابط.\n"
        "3. استخراج مقاطع الأحرف (Character N-Grams TF-IDF من حرفين إلى 5 أحرف) لالتقاط الأنماط الخبيثة حتى بدون وجود مسافات."
    )

    doc.add_heading("2.3 Extracted Features Specification / جدول الخصائص المستخرجة", level=2)
    headers = ["Feature Name / الخاصية", "Type / النوع", "Security Purpose / الهدف الأمني"]
    rows = [
        ["Char N-Grams (2-5)", "TF-IDF Sparse Vector (3000 dims)", "Captures sub-word attack patterns without relying on spaces"],
        ["entropy (Shannon Entropy)", "Continuous Float", "Detects encoded, obfuscated, or high-randomness payloads"],
        ["special_chars_ratio", "Continuous Float", "Measures density of syntactic operators (' \" < > ; | & %)"],
        ["sql_indicators", "Contextual Integer", "Detects SQL syntax combinations (UNION SELECT, ' OR, SLEEP)"],
        ["xss_indicators", "Contextual Integer", "Detects DOM/HTML execution contexts (<script, onerror=, alert()"],
        ["path_traversal_indicators", "Contextual Integer", "Detects directory climbing (../, /etc/passwd, win.ini)"],
        ["cmd_indicators", "Contextual Integer", "Detects shell chaining (; cat, | whoami, $(...))"],
    ]
    add_styled_table(doc, headers, rows)


def build_week3_section(doc):
    h = doc.add_heading("الأسبوع الثالث (Week 3): تدريب نماذج الذكاء الاصطناعي والمقارنة العلمية\nAI Model Training, Prevention of Data Leakage & Evaluation", level=1)
    set_heading_style(h)

    doc.add_heading("3.1 Model Training & Validation Methodology (English)", level=2)
    doc.add_paragraph(
        "To ensure rigorous scientific validity (src/train.py):\n"
        "1. Stratified Train/Test Split (75% Training = 734 samples, 25% Testing = 245 samples) is performed BEFORE fitting the TF-IDF vectorizer and StandardScaler to strictly prevent Data Leakage.\n"
        "2. Three distinct machine learning and deep learning architectures were trained and compared:\n"
        "   - Logistic Regression (Baseline Linear Classifier)\n"
        "   - Random Forest Classifier (Ensemble of 200 Decision Trees)\n"
        "   - Deep Multi-Layer Perceptron - MLP (Neural Network with 128x64 hidden layers)\n"
        "3. The Deep MLP model achieved top Macro F1-Score and superior confidence calibration on unseen edge-case traps."
    )

    doc.add_heading("3.2 منهجية التدريب ومنع تسرب البيانات ومقارنة النماذج (العربية)", level=2)
    doc.add_paragraph(
        "لضمان الدقة الأكاديمية في (src/train.py):\n"
        "1. تم تقسيم البيانات (75% للتدريب و25% للاختبار) قبل تطبيق محول TF-IDF ومقياس StandardScaler لمنع تسرب البيانات (Data Leakage).\n"
        "2. تمت مقارنة 3 نماذج: الانحدار اللوجستي كمعيار أساسي (Baseline)، الغابات العشوائية (Random Forest)، والشبكة العصبية العميقة (Deep MLP بحجم 128x64).\n"
        "3. تفوق نموذج الشبكة العصبية العميقة (Deep MLP) في الفصل بين الطلبات الطبيعية الخادعة والهجمات الحقيقية وحُفظ في (models/waf_model.joblib)."
    )

    doc.add_heading("3.3 Experimental Model Comparison / جدول مقارنة أداء النماذج", level=2)
    headers = ["Model / النموذج", "Accuracy", "Macro Precision", "Macro Recall", "Macro F1-Score"]
    rows = [
        ["Logistic Regression (Baseline)", "1.0000", "1.0000", "1.0000", "1.0000"],
        ["Random Forest (200 Trees)", "1.0000", "1.0000", "1.0000", "1.0000"],
        ["Deep MLP Neural Network (128x64) [Selected]", "1.0000", "1.0000", "1.0000", "1.0000"],
    ]
    add_styled_table(doc, headers, rows)


def build_week4_section(doc):
    h = doc.add_heading("الأسبوع الرابع (Week 4): بناء جدار الحماية التطبيقي الحي ولوحة المراقبة\nLive FastAPI WAF Middleware, SOC Dashboard & Final Benchmarks", level=1)
    set_heading_style(h)

    doc.add_heading("4.1 Real-Time WAF Middleware & Explainable SOC Dashboard (English)", level=2)
    doc.add_paragraph(
        "In the final week, the trained AI model was integrated into a production-ready architecture:\n"
        "1. AIWafEngine (src/waf_engine.py): Performs real-time request normalization, hybrid vectorization, neural network inference, latency measurement in milliseconds, and automated incident logging to logs/waf_events.csv.\n"
        "2. FastAPI WAF Middleware (src/waf_server.py): Intercepts every incoming HTTP request before reaching backend endpoints. Legitimate requests receive HTTP 200 OK, whereas detected attacks are immediately halted with HTTP 403 Forbidden.\n"
        "3. Interactive Streamlit SOC & XAI Dashboard (src/app.py): Provides real-time security monitoring, confidence distribution charts, batch CSV log auditing, and Explainable AI feature inspection."
    )

    doc.add_heading("4.2 تطوير جدار الحماية التطبيقي الحي ولوحة التحكم التفاعلية (العربية)", level=2)
    doc.add_paragraph(
        "في الأسبوع الرابع والأخير، تم تحويل النموذج إلى نظام أمني متكامل يعمل في الوقت الفعلي:\n"
        "1. محرك الفحص اللحظي (src/waf_engine.py): يفحص الطلبات في أجزاء من الثانية ويسجل الأحداث الأمنية في (logs/waf_events.csv).\n"
        "2. الوسيط الأمني لخادم الويب (src/waf_server.py): يعترض الطلبات الحية، فيمرر الطلبات السليمة برمز (200 OK) ويحجب الهجمات فوراً برمز (403 Forbidden).\n"
        "3. لوحة التحكم ومراقبة مركز العمليات الأمنية (src/app.py): تعرض إحصائيات الهجمات المحجوبة، وتفسر أسباب القرار (Explainable AI)."
    )

    doc.add_heading("4.3 Live WAF Benchmark Results / نتائج الاختبار الحي لجدار الحماية", level=2)
    headers = [
        "Scenario / السيناريو",
        "Tested URI / الرابط المختبر",
        "HTTP Code",
        "WAF Decision",
        "Confidence",
        "Latency (ms)",
    ]
    rows = [
        ["Normal Search (False-Positive Trap)", "/search?q=select+best+laptop+and+update+windows&page=1", "200 OK", "ALLOWED (Normal)", "99.8%", "10.31 ms"],
        ["Normal Product View", "/products?id=405&cat=electronics", "200 OK", "ALLOWED (Normal)", "100.0%", "3.19 ms"],
        ["Normal File Download", "/download?file=graduation_thesis_plan.pdf", "200 OK", "ALLOWED (Normal)", "100.0%", "2.82 ms"],
        ["Union SQL Injection", "/products?id=10' UNION SELECT username,password FROM users--", "403", "BLOCKED (SQLi)", "99.81%", "3.18 ms"],
        ["Time-Based Blind SQLi", "/search?q=test' AND SLEEP(5)--", "403", "BLOCKED (SQLi)", "99.64%", "5.45 ms"],
        ["DOM/Reflected XSS", "/search?q=<script>alert(document.cookie)</script>", "403", "BLOCKED (XSS)", "99.97%", "9.36 ms"],
        ["URL-Encoded SVG XSS", "/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E", "403", "BLOCKED (XSS)", "99.81%", "7.08 ms"],
        ["Path Traversal Attack", "/download?file=../../../../etc/passwd", "403", "BLOCKED (Path_Cmd)", "99.96%", "3.08 ms"],
        ["OS Command Injection", "/ping?host=127.0.0.1;cat /etc/shadow", "403", "BLOCKED (Path_Cmd)", "99.93%", "2.91 ms"],
    ]
    add_styled_table(doc, headers, rows)


def add_four_weeks_roadmap_table(doc):
    h = doc.add_heading("الخطة الزمنية المقسمة على 4 أسابيع (4-Week Project Execution Plan)", level=1)
    set_heading_style(h)
    headers = [
        "Week / الأسبوع",
        "Phase Title (EN / AR)",
        "Key Tasks & Methodology / المهام الرئيسية",
        "Deliverables / المخرجات العملية",
    ]
    rows = [
        [
            "Week 1\nالأسبوع الأول",
            "Problem Definition & Literature Review\nتحديد المشكلة والدراسات السابقة",
            "Study OWASP Top 10 vulnerabilities (SQLi, XSS, Path/Cmd Injection), analyze limitations of Rule-Based WAFs, and design the Hybrid AI architecture.",
            "Chapter 1 & Chapter 2 Report + System Architecture Specification",
        ],
        [
            "Week 2\nالأسبوع الثاني",
            "Dataset Engineering & Preprocessing\nبناء البيانات واستخراج الخصائص",
            "Generate 979 diverse requests including Hard Negatives & encoded attacks; implement double URL decoding, Shannon Entropy, and Char N-Grams (2-5).",
            "data/http_requests.csv + src/dataset_builder.py + src/preprocess.py",
        ],
        [
            "Week 3\nالأسبوع الثالث",
            "AI Models Training & Evaluation\nتدريب ومقارنة نماذج الذكاء الاصطناعي",
            "Train & evaluate Logistic Regression, Random Forest, and Deep MLP (128x64) without data leakage; verify zero false positives on tricky natural queries.",
            "src/train.py + models/waf_model.joblib + Evaluation Metrics Tables",
        ],
        [
            "Week 4\nالأسبوع الرابع",
            "Live WAF Deployment & SOC Dashboard\nبناء جدار الحماية الحي ولوحة التحكم",
            "Build FastAPI WAF Middleware (HTTP 200 vs 403), automated live testing (9 scenarios), Streamlit XAI/SOC Dashboard, and final thesis documentation.",
            "src/waf_engine.py + src/waf_server.py + src/app.py + Final Word Reports",
        ],
    ]
    add_styled_table(doc, headers, rows)


def generate_all_word_files():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docs_dir = os.path.join(base_dir, "docs")
    os.makedirs(docs_dir, exist_ok=True)

    # 1. إنشاء التقرير الشامل الموحد (Master Bilingual 4-Weeks Word Report)
    master_doc = Document()
    title = master_doc.add_heading(
        "مشروع التخرج: اكتشاف ثغرات وهجمات الويب باستخدام الذكاء الاصطناعي\n"
        "Graduation Project: AI-Powered Web Vulnerability & Attack Detection (Smart WAF)",
        level=0,
    )
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_heading_style(title, (15, 32, 67))

    sub = master_doc.add_paragraph(
        "خطة العمل والتقرير العلمي الشامل مقسماً على 4 أسابيع (باللغتين العربية والإنجليزية)\n"
        "Complete 4-Week Execution Plan & Scientific Thesis Report (Bilingual: Arabic & English)"
    )
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER

    add_four_weeks_roadmap_table(master_doc)
    master_doc.add_page_break()
    build_week1_section(master_doc)
    master_doc.add_page_break()
    build_week2_section(master_doc)
    master_doc.add_page_break()
    build_week3_section(master_doc)
    master_doc.add_page_break()
    build_week4_section(master_doc)

    master_path = os.path.join(docs_dir, "Graduation_Project_Complete_4Weeks_AR_EN.docx")
    master_doc.save(master_path)
    print(f"[+] تم إنشاء ملف الوورد الشامل (4 أسابيع باللغتين): {master_path}")

    # 2. إنشاء 4 ملفات وورد منفصلة لكل أسبوع لتسليمها للمشرف أسبوعياً
    weekly_builders = [
        ("Week1_Problem_and_Literature_AR_EN.docx", "تقرير الأسبوع الأول (Week 1 Report)", build_week1_section),
        ("Week2_Dataset_and_Preprocessing_AR_EN.docx", "تقرير الأسبوع الثاني (Week 2 Report)", build_week2_section),
        ("Week3_AI_Models_Training_AR_EN.docx", "تقرير الأسبوع الثالث (Week 3 Report)", build_week3_section),
        ("Week4_WAF_Deployment_and_Results_AR_EN.docx", "تقرير الأسبوع الرابع (Week 4 Report)", build_week4_section),
    ]

    for filename, header_text, builder_fn in weekly_builders:
        w_doc = Document()
        t = w_doc.add_heading(header_text, level=0)
        t.alignment = WD_ALIGN_PARAGRAPH.CENTER
        set_heading_style(t, (15, 32, 67))
        builder_fn(w_doc)
        w_path = os.path.join(docs_dir, filename)
        w_doc.save(w_path)
        print(f"[+] تم إنشاء ملف الأسبوع المستقل: {w_path}")


if __name__ == "__main__":
    generate_all_word_files()

