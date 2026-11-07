import os
import shutil
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor


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

    doc.add_heading("1.1 Executive Summary & Problem Statement (English)", level=2)
    doc.add_paragraph(
        "Modern web applications face sophisticated cyber attacks targeting both the HTTP application layer and backend source code, "
        "most notably SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal (LFI), and OS Command Injection (RCE). "
        "Traditional Rule-Based Web Application Firewalls (such as ModSecurity) suffer from two major limitations:\n"
        "1. High False Positive Rates: Blocking legitimate users and developers whose natural queries contain technical terms like 'select', 'update', or 'script'.\n"
        "2. Evasion via Multi-Layer Obfuscation: Attackers bypass static Regular Expressions using Double/Triple URL Encoding, SQL inline comments (/**/), and polyglot XSS payloads.\n"
        "Objective: Design and implement a comprehensive 3-pillar AI Web Vulnerability Discovery Platform (SentinelWAF v3.0) combining:\n"
        "(A) Real-Time AI HTTP Request WAF, (B) Deep URL, Header & HTML Form Vulnerability Scanner, and (C) AI Static Source Code Vulnerability Scanner (SAST)."
    )

    doc.add_heading("1.2 الملخص ومشكلة البحث وأهداف المشروع (العربية)", level=2)
    doc.add_paragraph(
        "تواجه تطبيقات الويب الحديثة هجمات سيبرانية متطورة تستهدف طبقة التطبيقات والكود البرمجي الخلفي، وأبرزها حقن قواعد البيانات (SQLi)، "
        "والبرمجة عبر المواقع (XSS)، واختراق المسارات وحقن الأوامر (Path Traversal & Command Injection).\n"
        "تعاني جدران الحماية التقليدية المعتمدة على القواعد الثابتة (Signature-based WAFs) من مشكلتين رئيسيتين:\n"
        "1. ارتفاع الإنذارات الكاذبة (False Positives): حظر المستخدمين الشرعيين والمطورين عند كتابة جمل بحث طبيعية تحتوي على مفردات مثل select أو update.\n"
        "2. سهولة التجاوز بالتمويه والتشفير المتعدد (Multi-layer Obfuscation).\n"
        "الهدف: بناء منصة ذكاء اصطناعي متكاملة (SentinelWAF v3.0) تضم 3 محركات مترابطة:\n"
        "أولاً: جدار حماية ذكي لتحليل طلبات HTTP لحظياً، ثانياً: فاحص عميق لروابط المواقع وترويسات الأمان ونماذج الإدخال (HTML Forms)، وثالثاً: فاحص للكود المصدري (AI SAST) يكتشف الأسطر البرمجية المصابة ويقترح الكود الآمن البديل."
    )

    doc.add_heading("1.3 Comparison with Related Work / مقارنة بالدراسات والأنظمة السابقة", level=2)
    headers = [
        "Feature / المعيار",
        "Traditional WAF (ModSecurity)",
        "Classic ML (Word TF-IDF)",
        "SentinelWAF v3.0 (مشروعنا المطور)",
    ]
    rows = [
        ["Analysis Method / طريقة الفحص", "Static Regex Rules", "Word-level Tokenization", "Char N-Grams (2-5) + 9 Contextual Features + Deep MLP"],
        ["Obfuscation Resistance / مقاومة التمويه", "Low (ضعيفة)", "Medium (متوسطة)", "Very High (فك تشفير ثلاثي + عشوائية شانون)"],
        ["False Positives / الإنذارات الكاذبة", "High (مرتفعة)", "Moderate (متوسطة)", "0.00% on Holdout Benign Traffic (124/124)"],
        ["URL & HTML Form Audit / فحص المواقع والنماذج", "Not Supported", "Not Supported", "Deep Header, Cookie, DOM Sink & CSRF Form Scanner"],
        ["Source Code Audit (SAST) / فحص الكود المصدري", "Not Supported", "Not Supported", "Line-by-Line Python/PHP/JS SAST + Automated Patching"],
    ]
    add_styled_table(doc, headers, rows)


def build_week2_section(doc):
    h = doc.add_heading("الأسبوع الثاني (Week 2): بناء قاعدة البيانات الموسعة وهندسة الخصائص السياقية\nExpanded Dataset Construction (1,543 Samples) & Contextual Feature Engineering", level=1)
    set_heading_style(h)

    doc.add_heading("2.1 Dataset Engineering & Normalization (English)", level=2)
    doc.add_paragraph(
        "In Week 2, we constructed an expanded, realistic dataset of 1,543 unique HTTP requests (data/http_requests.csv) including unseen Zero-Day holdout vectors distributed across 4 classes:\n"
        "- Normal (481 samples, 31.2%): Standard web traffic, REST/GraphQL calls, and challenging developer forum 'Hard Negatives' containing SQL/Linux/JS terms in benign contexts.\n"
        "- SQLi (360 samples, 23.3%): Union-based, boolean/time-based blind (SLEEP/pg_sleep/WAITFOR), hex-encoded, and comment-split (UnIoN/**/SeLeCt) payloads.\n"
        "- Path_Cmd_Attack (352 samples, 22.8%): Directory traversal (..%252f..%252fetc/passwd, php://filter), and OS command chaining (; cat, | whoami, && ls).\n"
        "- XSS (350 samples, 22.7%): Polyglot payloads, SVG/MathML tags, event handlers, and DOM XSS vectors.\n\n"
        "Preprocessing Pipeline (src/preprocess.py):\n"
        "1. 3-Layer Recursive URL Decoding (urllib.parse.unquote_plus) and lowercase normalization.\n"
        "2. Shannon Entropy calculation H(X) to measure payload randomness and obfuscation.\n"
        "3. Contextual Syntactic Indicators that match multi-token attack structures rather than isolated English words."
    )

    doc.add_heading("2.2 تجهيز البيانات الموسعة (1,543 عينة) واستخراج الخصائص الهجينة (العربية)", level=2)
    doc.add_paragraph(
        "تم بناء قاعدة بيانات موسعة وواقعية تضم 1,543 طلباً فريداً غير مكرر في الملف (data/http_requests.csv)، موزعة على 4 فئات (481 طلب طبيعي شامل لطلبات المطورين الخادعة، 360 هجوم SQLi، 352 هجوم اختراق مسارات وأوامر، و350 هجوم XSS)، بالإضافة إلى مجموعة اختبار Zero-Day غير مرئية.\n"
        "خطوات المعالجة واستخراج الخصائص في (src/preprocess.py):\n"
        "1. فك التشفير الثلاثي المتكرر (3x Recursive URL Decoding) لإحباط محاولات التمويه المزدوج.\n"
        "2. حساب عشوائية شانون (Shannon Entropy) ونسبة الرموز الخاصة والأرقام إلى طول الرابط.\n"
        "3. استخراج مقاطع الأحرف (Character N-Grams TF-IDF من حرفين إلى 5 أحرف) لالتقاط الأنماط الخبيثة حتى بدون وجود مسافات."
    )

    doc.add_heading("2.3 Extracted Features Specification / جدول الخصائص المستخرجة", level=2)
    headers = ["Feature Name / الخاصية", "Type / النوع", "Security Purpose / الهدف الأمني"]
    rows = [
        ["Char N-Grams (2-5)", "TF-IDF L2 Normalized Vector (3000 dims)", "Captures sub-word attack patterns without relying on spaces"],
        ["entropy (Shannon Entropy)", "Continuous Float", "Detects encoded, obfuscated, or high-randomness payloads"],
        ["special_chars_ratio", "Continuous Float", "Measures density of syntactic operators (' \" < > ; | & %)"],
        ["sql_indicators", "Contextual Integer", "Detects SQL syntax combinations (UNION SELECT, ' OR, pg_sleep, 0x...)"],
        ["xss_indicators", "Contextual Integer", "Detects DOM/HTML execution contexts (<script, onerror=, alert(), eval()"],
        ["path_traversal_indicators", "Contextual Integer", "Detects directory climbing (../, /etc/passwd, php://filter)"],
        ["cmd_indicators", "Contextual Integer", "Detects shell chaining (; cat, | whoami, $(...))"],
    ]
    add_styled_table(doc, headers, rows)


def build_week3_section(doc):
    h = doc.add_heading("الأسبوع الثالث (Week 3): تدريب نماذج الذكاء الاصطناعي وتصدير الأوزان السحابية\nAI Model Training, Zero-Day Evaluation & Cloud Weights Export", level=1)
    set_heading_style(h)

    doc.add_heading("3.1 Model Training, Zero-Day Holdout & Cloud Weights Export (English)", level=2)
    doc.add_paragraph(
        "To ensure rigorous scientific validity (src/train.py):\n"
        "1. Stratified Train/Test Split + Unseen Zero-Day Holdout (1,149 Training samples, 394 Testing samples) is performed BEFORE fitting the TF-IDF vectorizer and StandardScaler to strictly prevent Data Leakage.\n"
        "2. Three distinct machine learning and deep learning architectures were trained and compared:\n"
        "   - Logistic Regression (Baseline Linear Classifier): 98.98% Accuracy, 0.9900 Macro F1\n"
        "   - Random Forest Classifier (Ensemble of 100 Trees): 99.75% Accuracy, 0.9976 Macro F1\n"
        "   - Deep Multi-Layer Perceptron - MLP (128x64 Neural Network): 99.75% Accuracy, 0.9972 Macro F1, and 0.00% False Positives (124/124 Normal requests correctly allowed).\n"
        "3. Real Cloud Weights Export (api/model_weights.json): We exported the trained vocabulary, IDF vector, StandardScaler mean/scale, and weight matrix (16.8 KB JSON) to execute genuine mathematical forward-pass inference (W·x + b -> Softmax) on Vercel Serverless."
    )

    doc.add_heading("3.2 منهجية التدريب ومقارنة النماذج وتصدير الأوزان للسحابة (العربية)", level=2)
    doc.add_paragraph(
        "لضمان الدقة الأكاديمية في (src/train.py):\n"
        "1. تم فصل بيانات التدريب (1,149 عينة) عن بيانات الاختبار الموسعة (394 عينة تشمل هجمات Zero-Day لم يرها النموذج أثناء التدريب) قبل ملائمة TF-IDF و StandardScaler لمنع تسرب البيانات.\n"
        "2. حقق نموذج الشبكة العصبية العميقة (Deep MLP 128x64) دقة 99.75% مع صفر بالمئة (0.00%) إنذارات كاذبة على الطلبات الطبيعية (124 من 124).\n"
        "3. تم تصدير الأوزان الرياضية الفعلية للنموذج إلى الملف السحابي (api/model_weights.json بحجم 16.8 كيلوبايت) لتشغيل معادلات الضرب المصفوفي ودالة Softmax مباشرة على منصة Vercel."
    )

    doc.add_heading("3.3 Experimental Model Comparison / جدول مقارنة أداء النماذج (N = 394 Test Set)", level=2)
    headers = ["Model / النموذج", "Accuracy", "Macro Precision", "Macro Recall", "Macro F1", "Normal FP Rate"]
    rows = [
        ["Deep MLP Neural Network (128x64) [Primary]", "0.9975", "0.9973", "0.9972", "0.9972", "0.00% (0/124)"],
        ["Random Forest (100 Trees)", "0.9975", "0.9972", "0.9980", "0.9976", "0.81% (1/124)"],
        ["Logistic Regression (L2 Baseline)", "0.9898", "0.9904", "0.9896", "0.9900", "0.81% (1/124)"],
    ]
    add_styled_table(doc, headers, rows)


def build_week4_section(doc):
    h = doc.add_heading("الأسبوع الرابع (Week 4): جدار الحماية الحي، فاحص نماذج المواقع، وفاحص الكود المصدري SAST\nLive WAF Middleware, Deep HTML Form Scanner & AI Source Code SAST", level=1)
    set_heading_style(h)

    doc.add_heading("4.1 Multi-Engine Security Platform: WAF + DAST Form Auditor + SAST Code Scanner (English)", level=2)
    doc.add_paragraph(
        "In the final phase, the platform was expanded into a complete 5-tab bilingual console (SentinelWAF v3.0):\n"
        "1. Real-Time FastAPI WAF Middleware (src/waf_server.py & src/waf_engine.py): Intercepts incoming HTTP traffic, allowing legitimate requests (HTTP 200 OK) and blocking attacks (HTTP 403 Forbidden) in 1.8ms - 10.3ms.\n"
        "2. Deep URL, Header & HTML Form Vulnerability Scanner (src/url_scanner.py): Inspects HTTPS transport, CSP/HSTS/X-Frame-Options headers, cookies, DOM XSS sinks, and extracts all HTML <form> and <input> elements to detect missing Anti-CSRF tokens.\n"
        "3. AI Static Source Code Vulnerability Scanner - SAST (src/code_scanner.py): Analyzes Python, PHP, and Node.js backend code line-by-line to detect SQLi (CWE-89), XSS (CWE-79), Command Injection (CWE-78), eval() (CWE-94), LFI (CWE-22), and Hardcoded Secrets (CWE-798), generating instant secure code patches."
    )

    doc.add_heading("4.2 المنصة المتكاملة: جدار الحماية + فاحص النماذج + فاحص الكود المصدري SAST (العربية)", level=2)
    doc.add_paragraph(
        "في المرحلة الرابعة، تم دمج ثلاث وحدات عملية داخل منصة (SentinelWAF v3.0) ثنائية اللغة:\n"
        "1. الوسيط الأمني لجدار الحماية (src/waf_server.py): يعترض الطلبات الحية، فيمرر الطلبات السليمة برمز (200 OK) ويحجب الهجمات فوراً برمز (403 Forbidden).\n"
        "2. الفاحص العميق للمواقع ونماذج الإدخال (src/url_scanner.py): يحلل ترويسات الأمان والكوكيز ويستخرج جميع نماذج <form> وحقول <input> لكشف مخاطر CSRF و DOM XSS.\n"
        "3. فاحص الكود المصدري بالذكاء الاصطناعي (src/code_scanner.py - SAST): يفحص أكواد Python و PHP و Node.js سطراً بسطر، ويحدد رقم السطر المصاب وتصنيف CWE/OWASP ويولد الكود الآمن البديل (Secure Patch) تلقائياً."
    )

    doc.add_heading("4.3 Live WAF Benchmark Results / نتائج الاختبار الحي لجدار الحماية", level=2)
    headers = [
        "Scenario / السيناريو",
        "Tested URI / الرابط المختبر",
        "HTTP Code",
        "WAF Decision",
        "Confidence",
        "Latency",
    ]
    rows = [
        ["Normal Search (False-Positive Trap)", "/search?q=select+best+laptop+and+update+windows&page=1", "200 OK", "ALLOWED (Normal)", "99.93%", "2.31 ms"],
        ["Normal Product View", "/products?id=405&cat=electronics", "200 OK", "ALLOWED (Normal)", "99.98%", "1.89 ms"],
        ["Normal File Download", "/download?file=graduation_thesis_plan.pdf", "200 OK", "ALLOWED (Normal)", "99.95%", "1.82 ms"],
        ["Union SQL Injection", "/products?id=10' UNION SELECT username,password FROM users--", "403", "BLOCKED (SQLi)", "99.99%", "2.18 ms"],
        ["Comment-Split Obfuscated SQLi", "/api/v1/user?id=42' UnIoN/**/aLl/**/SeLeCt 1,user(),3--", "403", "BLOCKED (SQLi)", "99.96%", "2.45 ms"],
        ["DOM/Reflected XSS", "/search?q=<script>alert(document.cookie)</script>", "403", "BLOCKED (XSS)", "99.97%", "2.36 ms"],
        ["URL-Encoded SVG XSS", "/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E", "403", "BLOCKED (XSS)", "99.94%", "2.08 ms"],
        ["Double-Encoded Path Traversal", "/download?file=..%252f..%252f..%252fetc%252fpasswd", "403", "BLOCKED (Path_Cmd)", "99.98%", "2.04 ms"],
        ["OS Command Injection", "/ping?host=127.0.0.1;cat /etc/shadow", "403", "BLOCKED (Path_Cmd)", "99.97%", "1.91 ms"],
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
            "Study OWASP Top 10 vulnerabilities (SQLi, XSS, LFI/RCE, CSRF), analyze limitations of Rule-Based WAFs, and design the 3-pillar Hybrid AI architecture.",
            "Chapter 1 & Chapter 2 Report + System Architecture Specification",
        ],
        [
            "Week 2\nالأسبوع الثاني",
            "Dataset Engineering & Preprocessing\nبناء البيانات الموسعة واستخراج الخصائص",
            "Generate 1,543 unique requests including developer Hard Negatives & Zero-Day attacks; implement 3x URL decoding, Shannon Entropy, and Char N-Grams (2-5).",
            "data/http_requests.csv + src/dataset_builder.py + src/preprocess.py",
        ],
        [
            "Week 3\nالأسبوع الثالث",
            "AI Models Training & Cloud Export\nتدريب النماذج وتصدير الأوزان السحابية",
            "Train & evaluate Logistic Regression, Random Forest, and Deep MLP (128x64) on N=394 holdout split (99.75% accuracy, 0% FP); export real weights to api/model_weights.json.",
            "src/train.py + models/waf_model.joblib + api/model_weights.json",
        ],
        [
            "Week 4\nالأسبوع الرابع",
            "Live WAF, Form Scanner & SAST Engine\nجدار الحماية وفاحص النماذج والكود المصدري",
            "Build FastAPI WAF Middleware, Deep HTML Form & Header Scanner, AI Source Code SAST Scanner (CWE/OWASP + Auto-Patch), and deploy SentinelWAF v3.0 to Vercel.",
            "src/waf_server.py + src/url_scanner.py + src/code_scanner.py + index.html",
        ],
    ]
    add_styled_table(doc, headers, rows)


def generate_all_word_files():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docs_dir = os.path.join(base_dir, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    desktop_dir = r"C:\Users\lenovo\Desktop\AI_Web_Vulnerability_Graduation_Project"
    os.makedirs(desktop_dir, exist_ok=True)

    master_doc = Document()
    title = master_doc.add_heading(
        "مشروع التخرج: اكتشاف ثغرات وهجمات الويب باستخدام الذكاء الاصطناعي\n"
        "Graduation Project: AI-Powered Web Vulnerability Discovery, Smart WAF & SAST Platform (v3.0)",
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
    shutil.copy2(master_path, os.path.join(desktop_dir, "Graduation_Project_Complete_4Weeks_AR_EN.docx"))
    print(f"[+] تم تحديث ملف الوورد الشامل ونسخه إلى سطح المكتب: {master_path}")

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
        shutil.copy2(w_path, os.path.join(desktop_dir, filename))
        print(f"[+] تم تحديث ملف الأسبوع المستقل ونسخه إلى سطح المكتب: {w_path}")


if __name__ == "__main__":
    generate_all_word_files()
