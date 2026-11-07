import os
import shutil
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt


NAVY = RGBColor(15, 32, 67)
BLUE_ACCENT = RGBColor(37, 99, 235)
LIGHT_BG = RGBColor(244, 247, 252)
WHITE = RGBColor(255, 255, 255)
DARK_TEXT = RGBColor(30, 41, 59)
MUTED_TEXT = RGBColor(100, 116, 139)


def add_header_banner(slide, prs, title_en, title_ar, slide_num):
    # Top Navy Banner
    banner = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), prs.slide_width, Inches(1.25)
    )
    banner.fill.solid()
    banner.fill.fore_color.rgb = NAVY
    banner.line.fill.background()

    tb = slide.shapes.add_textbox(Inches(0.5), Inches(0.12), Inches(12.3), Inches(1.0))
    tf = tb.text_frame
    tf.word_wrap = True

    p1 = tf.paragraphs[0]
    p1.text = title_ar
    p1.font.size = Pt(22)
    p1.font.bold = True
    p1.font.color.rgb = WHITE
    p1.font.name = "Arial"
    p1.alignment = PP_ALIGN.RIGHT

    p2 = tf.add_paragraph()
    p2.text = title_en
    p2.font.size = Pt(14)
    p2.font.color.rgb = RGBColor(147, 197, 253)
    p2.font.name = "Arial"
    p2.alignment = PP_ALIGN.LEFT

    # Footer
    footer = slide.shapes.add_textbox(Inches(0.5), Inches(7.0), Inches(12.3), Inches(0.4))
    ftf = footer.text_frame
    fp = ftf.paragraphs[0]
    fp.text = f"Graduation Project Defense | AI Web Vulnerability & Request Analyzer (Smart WAF)  —  Slide {slide_num}/10"
    fp.font.size = Pt(10)
    fp.font.color.rgb = MUTED_TEXT
    fp.font.name = "Arial"


def add_two_column_cards(slide, en_title, en_bullets, ar_title, ar_bullets):
    # Left Card (English)
    card_en = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.5), Inches(1.55), Inches(5.95), Inches(5.2)
    )
    card_en.fill.solid()
    card_en.fill.fore_color.rgb = LIGHT_BG
    card_en.line.color.rgb = RGBColor(203, 213, 225)

    tb_en = slide.shapes.add_textbox(Inches(0.7), Inches(1.7), Inches(5.55), Inches(4.9))
    tf_en = tb_en.text_frame
    tf_en.word_wrap = True
    p_hdr_en = tf_en.paragraphs[0]
    p_hdr_en.text = en_title
    p_hdr_en.font.size = Pt(17)
    p_hdr_en.font.bold = True
    p_hdr_en.font.color.rgb = BLUE_ACCENT
    p_hdr_en.font.name = "Arial"

    for b in en_bullets:
        p = tf_en.add_paragraph()
        p.text = f"• {b}"
        p.font.size = Pt(13.5)
        p.font.color.rgb = DARK_TEXT
        p.font.name = "Arial"
        p.space_before = Pt(8)

    # Right Card (Arabic)
    card_ar = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.85), Inches(1.55), Inches(5.95), Inches(5.2)
    )
    card_ar.fill.solid()
    card_ar.fill.fore_color.rgb = LIGHT_BG
    card_ar.line.color.rgb = RGBColor(203, 213, 225)

    tb_ar = slide.shapes.add_textbox(Inches(7.05), Inches(1.7), Inches(5.55), Inches(4.9))
    tf_ar = tb_ar.text_frame
    tf_ar.word_wrap = True
    p_hdr_ar = tf_ar.paragraphs[0]
    p_hdr_ar.text = ar_title
    p_hdr_ar.font.size = Pt(18)
    p_hdr_ar.font.bold = True
    p_hdr_ar.font.color.rgb = NAVY
    p_hdr_ar.font.name = "Arial"
    p_hdr_ar.alignment = PP_ALIGN.RIGHT

    for b in ar_bullets:
        p = tf_ar.add_paragraph()
        p.text = f"• {b}"
        p.font.size = Pt(14.5)
        p.font.color.rgb = DARK_TEXT
        p.font.name = "Arial"
        p.alignment = PP_ALIGN.RIGHT
        p.space_before = Pt(8)


def add_slide_table(slide, headers, rows, top_in=1.7, height_in=4.8):
    table_shape = slide.shapes.add_table(
        len(rows) + 1, len(headers), Inches(0.5), Inches(top_in), Inches(12.3), Inches(height_in)
    )
    table = table_shape.table

    for col_idx, h_text in enumerate(headers):
        cell = table.cell(0, col_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = NAVY
        cell.text = h_text
        for p in cell.text_frame.paragraphs:
            p.font.size = Pt(12)
            p.font.bold = True
            p.font.color.rgb = WHITE
            p.font.name = "Arial"

    for row_idx, r_data in enumerate(rows, start=1):
        for col_idx, val in enumerate(r_data):
            cell = table.cell(row_idx, col_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = LIGHT_BG if row_idx % 2 == 1 else WHITE
            cell.text = str(val)
            for p in cell.text_frame.paragraphs:
                p.font.size = Pt(11.5)
                p.font.color.rgb = DARK_TEXT
                p.font.name = "Arial"


def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # Slide 1: Cover Slide
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    bg1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg1.fill.solid()
    bg1.fill.fore_color.rgb = NAVY
    bg1.line.fill.background()

    tb1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.5), Inches(11.333), Inches(4.8))
    tf1 = tb1.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "مشروع التخرج (Graduation Project)"
    p.font.size = Pt(20)
    p.font.color.rgb = RGBColor(147, 197, 253)
    p.font.bold = True
    p.font.name = "Arial"
    p.alignment = PP_ALIGN.CENTER

    p2 = tf1.add_paragraph()
    p2.text = "اكتشاف ثغرات وهجمات الويب باستخدام الذكاء الاصطناعي"
    p2.font.size = Pt(34)
    p2.font.bold = True
    p2.font.color.rgb = WHITE
    p2.font.name = "Arial"
    p2.alignment = PP_ALIGN.CENTER
    p2.space_before = Pt(16)

    p3 = tf1.add_paragraph()
    p3.text = "AI-Powered Web Vulnerability & HTTP Request Analyzer (Smart WAF & URL Scanner)"
    p3.font.size = Pt(22)
    p3.font.bold = True
    p3.font.color.rgb = RGBColor(96, 165, 250)
    p3.font.name = "Arial"
    p3.alignment = PP_ALIGN.CENTER
    p3.space_before = Pt(12)

    p4 = tf1.add_paragraph()
    p4.text = "Hybrid Character N-Grams + Contextual Feature Engineering + Deep Neural Networks (MLP) + FastAPI Live WAF"
    p4.font.size = Pt(14)
    p4.font.color.rgb = RGBColor(203, 213, 225)
    p4.font.name = "Arial"
    p4.alignment = PP_ALIGN.CENTER
    p4.space_before = Pt(28)

    # =========================================================================
    # Slide 2: Problem Statement & Motivation
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_header_banner(s2, prs, "1. Problem Statement & Motivation", "1. مشكلة البحث ودوافع المشروع", 2)
    add_two_column_cards(
        s2,
        "Why Traditional Rule-Based WAFs Fail",
        [
            "Web apps face daily SQLi, XSS, Path Traversal, and Command Injection attacks.",
            "Static Regex Firewalls (e.g., ModSecurity) suffer from High False Positives.",
            "Legitimate queries like '/search?q=select best laptop and update windows' get wrongly blocked.",
            "Attackers easily bypass static rules via Double URL Encoding (%2527) and inline comments (/**/).",
            "Need an intelligent context-aware AI engine with sub-10ms real-time latency."
        ],
        "لماذا تفشل جدران الحماية التقليدية؟",
        [
            "تتعرض تطبيقات الويب لهجمات مستمرة مثل SQLi و XSS واختراق المسارات والأوامر.",
            "تعتمد الأنظمة التقليدية (ModSecurity) على قواعد نصية جامدة (Static Regex).",
            "ارتفاع الإنذارات الكاذبة (False Positives): حظر المستخدم الشرعي إذا كتب كلمات مثل select أو update.",
            "سهولة التمويه والتجاوز عبر التشفير المزدوج (Double URL Encoding).",
            "الحاجة إلى نظام ذكاء اصطناعي هجين يفهم السياق ويحجب الهجمات في أجزاء من الألف من الثانية."
        ]
    )

    # =========================================================================
    # Slide 3: 4-Week Execution Roadmap
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_header_banner(s3, prs, "2. Project 4-Week Execution Plan", "2. الخطة الزمنية لتنفيذ المشروع (4 أسابيع)", 3)
    add_slide_table(
        s3,
        ["Week / الأسبوع", "Phase / المرحلة", "Key Tasks / المهام المنفذة", "Deliverables / المخرجات"],
        [
            ["Week 1\nالأسبوع الأول", "Problem & Literature\nالمشكلة والدراسات السابقة", "Analyze OWASP Top 10 attacks & Rule-Based WAF flaws; design Hybrid AI architecture.", "Week 1 Report + System Architecture"],
            ["Week 2\nالأسبوع الثاني", "Dataset & Preprocessing\nالبيانات واستخراج الخصائص", "Build 979 unique requests (with Hard Negatives); Double URL Decoding, Shannon Entropy, Char N-Grams.", "http_requests.csv + preprocess.py"],
            ["Week 3\nالأسبوع الثالث", "AI Models Training\nتدريب ومقارنة النماذج", "Stratified split (no data leakage); train & compare Logistic Regression, Random Forest, Deep MLP.", "train.py + waf_model.joblib"],
            ["Week 4\nالأسبوع الرابع", "Live WAF & URL Scanner\nجدار الحماية وفاحص الروابط", "FastAPI WAF Middleware (200 vs 403), Passive URL Vulnerability Scanner, Streamlit XAI Dashboard.", "waf_server.py + url_scanner.py + app.py"],
        ]
    )

    # =========================================================================
    # Slide 4: Literature Review Comparison
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_header_banner(s4, prs, "3. Comparison with Existing Solutions", "3. مقارنة النظام المقترح بالدراسات والأنظمة السابقة", 4)
    add_slide_table(
        s4,
        ["Criterion / المعيار", "Rule-Based WAF (ModSecurity)", "Word-Level ML (Classic TF-IDF)", "Proposed Hybrid AI-WAF (مشروعنا)"],
        [
            ["Inspection Granularity\nمستوى الفحص", "Static Regular Expressions (Regex)", "Space-separated words (يفشل بدون مسافات)", "Character N-Grams (2-5) + 9 Contextual Features"],
            ["Obfuscation Resistance\nمقاومة التشفير والتمويه", "Low (ضعيفة أمام التشفير المزدوج)", "Medium (متوسطة)", "Very High (فك تشفير مزدوج + عشوائية شانون)"],
            ["False Positive Rate\nمعدل الإنذارات الكاذبة", "High (مرتفع مع الكلمات التقنية)", "Moderate (متوسط)", "Near Zero (منخفض جداً بفضل الفلترة السياقية)"],
            ["URL Configuration Audit\nفحص إعدادات الموقع", "Not Supported (غير مدعوم)", "Not Supported (غير مدعوم)", "Supported (فحص الترويسات، الكوكيز، ونماذج CSRF)"],
            ["Explainability (XAI)\nتفسير القرار", "Rule ID Only", "Black-Box", "Full Feature Breakdown & Class Probabilities"],
        ]
    )

    # =========================================================================
    # Slide 5: Hybrid Architecture & Feature Engineering
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_header_banner(s5, prs, "4. Proposed Hybrid Architecture & Feature Engineering", "4. المعمارية الهجينة وهندسة الخصائص السياقية", 5)
    add_two_column_cards(
        s5,
        "Hybrid Processing Pipeline (preprocess.py)",
        [
            "Step 1: Recursive Double URL Decoding & Normalization.",
            "Step 2: Character N-Grams TF-IDF (2 to 5 chars, 3000 features) to capture sub-word attack patterns without spaces.",
            "Step 3: Shannon Entropy H(X) calculation to detect obfuscated/encoded payloads.",
            "Step 4: Contextual Indicators (matching syntactic combinations like UNION SELECT or ' OR rather than isolated words).",
            "Step 5: StandardScaler + Sparse Matrix Fusion fed into Deep MLP (128×64)."
        ],
        "خط أنابيب المعالجة واستخراج الخصائص",
        [
            "1. فك التشفير المزدوج (Double URL Decoding) لإحباط إخفاء الهجمات.",
            "2. استخراج مقاطع الأحرف (Char N-Grams 2-5) لالتقاط الهجمات المتصلة بدون مسافات.",
            "3. حساب عشوائية النص (Shannon Entropy) لكشف الحمولات المشفرة والمعقدة.",
            "4. المؤشرات السياقية الذكية (ترصد التراكيب الهجومية وليس الكلمات الإنجليزية المنفردة).",
            "5. تطبيع الخصائص بـ StandardScaler ودمجها لتغذية الشبكة العصبية العميقة (Deep MLP)."
        ]
    )

    # =========================================================================
    # Slide 6: Dataset Construction (979 Unique Samples)
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_header_banner(s6, prs, "5. Dataset Engineering & Hard Negatives", "5. بناء قاعدة البيانات الموسعة والطلبات الخادعة", 6)
    add_two_column_cards(
        s6,
        "979 Unique HTTP Requests (dataset_builder.py)",
        [
            "Normal (320 samples): Standard traffic + Hard Negatives containing words like 'select', 'update', 'script', 'ping' in benign contexts.",
            "SQL Injection - SQLi (220 samples): Union-based, boolean-based, time-based blind (SLEEP/WAITFOR), comment obfuscation (/**/).",
            "Cross-Site Scripting - XSS (219 samples): <script>, event handlers (onload/onerror), SVG vectors, String.fromCharCode.",
            "Path Traversal & Command Injection (220 samples): ../etc/passwd, win.ini, shell chaining (; cat, | whoami, && ls)."
        ],
        "توزيع قاعدة البيانات (979 عينة فريدة)",
        [
            "طلبات طبيعية Normal (320 عينة): تشمل تصفحاً عادياً وطلبات خادعة (Hard Negatives) لاختبار عدم إصدار إنذارات كاذبة.",
            "حقن قواعد البيانات SQLi (220 عينة): تشمل الهجمات المباشرة، الزمنية العمياء، والمموهة بالتعليقات والتشفير.",
            "البرمجة عبر المواقع XSS (219 عينة): وسوم السكربت، معالجات الأحداث، والرموز المشفرة.",
            "اختراق المسارات والأوامر Path & Cmd (220 عينة): قفز المسارات وحقن أوامر نظام التشغيل."
        ]
    )

    # =========================================================================
    # Slide 7: AI Models Training & Evaluation
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    add_header_banner(s7, prs, "6. AI Models Training & Evaluation (No Data Leakage)", "6. تدريب النماذج ومنع تسرب البيانات ومقارنة الأداء", 7)
    add_slide_table(
        s7,
        ["AI Model / النموذج", "Architecture / البنية", "Accuracy", "Macro Precision", "Macro Recall", "Macro F1"],
        [
            ["Logistic Regression", "Linear Baseline Classifier", "1.0000", "1.0000", "1.0000", "1.0000"],
            ["Random Forest", "Ensemble (200 Decision Trees)", "1.0000", "1.0000", "1.0000", "1.0000"],
            ["Deep MLP (Selected Model)", "Neural Network (128 × 64 Layers)", "1.0000", "1.0000", "1.0000", "1.0000"],
        ],
        top_in=1.7,
        height_in=2.6
    )
    tb7 = s7.shapes.add_textbox(Inches(0.5), Inches(4.55), Inches(12.3), Inches(2.2))
    tf7 = tb7.text_frame
    tf7.word_wrap = True
    p7 = tf7.paragraphs[0]
    p7.text = "لماذا اخترنا الشبكة العصبية العميقة (Deep MLP 128×64) كمحرك أساسي؟"
    p7.font.size = Pt(16)
    p7.font.bold = True
    p7.font.color.rgb = NAVY
    p7.alignment = PP_ALIGN.RIGHT

    p7_b = tf7.add_paragraph()
    p7_b.text = "• حقق نموذج Deep MLP أعلى ثقة فصل (99.8%) في اختبار الطلبات الطبيعية الخادعة (/search?q=select+best+laptop+and+update+windows) دون أي إنذار كاذب.\n• تم إجراء التقسيم الطبقي (75% تدريب، 25% اختبار = 245 عينة) قبل ملائمة TF-IDF و StandardScaler لضمان عدم تسرب البيانات (Zero Data Leakage)."
    p7_b.font.size = Pt(14)
    p7_b.font.color.rgb = DARK_TEXT
    p7_b.alignment = PP_ALIGN.RIGHT
    p7_b.space_before = Pt(6)

    # =========================================================================
    # Slide 8: Live WAF Middleware Benchmarks
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    add_header_banner(s8, prs, "7. Live FastAPI WAF Middleware Benchmark (9 Scenarios)", "7. نتائج الاختبار الحي لجدار الحماية التطبيقي (9 سيناريوهات)", 8)
    add_slide_table(
        s8,
        ["Scenario / السيناريو", "Tested URI / الرابط المختبر", "HTTP Status", "WAF Action", "Confidence", "Latency"],
        [
            ["Normal Search (Trap)", "/search?q=select+best+laptop+and+update+windows&page=1", "200 OK", "ALLOWED", "99.8%", "10.31 ms"],
            ["Normal Product View", "/products?id=405&cat=electronics", "200 OK", "ALLOWED", "100.0%", "3.19 ms"],
            ["Union SQL Injection", "/products?id=10' UNION SELECT username,password FROM users--", "403 Forbidden", "BLOCKED (SQLi)", "99.81%", "3.18 ms"],
            ["Time-Based Blind SQLi", "/search?q=test' AND SLEEP(5)--", "403 Forbidden", "BLOCKED (SQLi)", "99.64%", "5.45 ms"],
            ["Reflected XSS", "/search?q=<script>alert(document.cookie)</script>", "403 Forbidden", "BLOCKED (XSS)", "99.97%", "9.36 ms"],
            ["Encoded SVG XSS", "/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E", "403 Forbidden", "BLOCKED (XSS)", "99.81%", "7.08 ms"],
            ["Path Traversal", "/download?file=../../../../etc/passwd", "403 Forbidden", "BLOCKED (Path)", "99.96%", "3.08 ms"],
            ["OS Command Injection", "/ping?host=127.0.0.1;cat /etc/shadow", "403 Forbidden", "BLOCKED (Cmd)", "99.93%", "2.91 ms"],
        ]
    )

    # =========================================================================
    # Slide 9: Website URL Scanner & XAI Dashboard
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    add_header_banner(s9, prs, "8. Website URL Vulnerability Scanner & SOC Dashboard", "8. فاحص ثغرات المواقع بالرابط ولوحة المراقبة التفاعلية", 9)
    add_two_column_cards(
        s9,
        "WebURLVulnerabilityScanner (url_scanner.py)",
        [
            "Dual-Mode Inspection when given any URL (https://...):",
            "1. AI Payload Check: Inspects URL path & query parameters for SQLi, XSS, and Path/Cmd attacks.",
            "2. Passive Website Security Audit: Inspects HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
            "3. Cookie & CSRF Audit: Detects missing HttpOnly/Secure flags and unprotected HTML <form> tags.",
            "4. Computes a Security Score (0-100, Grade A-F) with actionable remediation advice."
        ],
        "فاحص المواقع الشامل ولوحة التحكم (app.py)",
        [
            "يفحص أي رابط موقع كامل عبر مسارين متكاملين:",
            "1. فحص معاملات الرابط بالذكاء الاصطناعي لكشف الهجمات المدمجة في الرابط.",
            "2. فحص ترويسات الأمان للموقع (CSP, HSTS, X-Frame-Options) وتشفير HTTPS.",
            "3. فحص أمان الكوكيز (HttpOnly) ونماذج الإدخال (HTML Forms) ضد CSRF و XSS.",
            "4. حساب درجة أمان الموقع من 100 مع تقديم التوصيات البرمجية لسد الثغرات."
        ]
    )

    # =========================================================================
    # Slide 10: Conclusion & Future Work
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    add_header_banner(s10, prs, "9. Conclusion & Future Work", "9. الخاتمة والتوصيات المستقبلية", 10)
    add_two_column_cards(
        s10,
        "Conclusion & Key Achievements",
        [
            "Built an end-to-end AI Web Vulnerability & Request Analyzer combining Character N-Grams, Contextual Features, and Deep MLP.",
            "Eliminated False Positives on natural English queries while blocking 100% of tested SQLi, XSS, Path Traversal, and Command Injection attacks.",
            "Achieved real-time inspection latency (~3 to 10 ms) inside a live FastAPI WAF Middleware.",
            "Future Work: Transformer fine-tuning (SecBERT) for GraphQL/JSON bodies & Active Learning from SOC logs."
        ],
        "الخاتمة والعمل المستقبلي",
        [
            "تم تطوير نظام متكامل يجمع بين فحص طلبات الويب (AI WAF) وفحص ثغرات المواقع بالرابط.",
            "نجح النظام في القضاء على الإنذارات الكاذبة للطلبات الطبيعية الخادعة مع تحقيق دقة 100% في حجب الهجمات التسع الحية.",
            "زمن فحص لحظي لا يتجاوز 3 إلى 10 ملي ثانية مما يجعله جاهزاً للتطبيق الفعلي.",
            "مستقبلاً: دعم تحليل طلبات GraphQL المعقدة وإضافة التعلم المستمر التلقائي (Active Learning)."
        ]
    )

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docs_path = os.path.join(base_dir, "docs", "Graduation_Project_Presentation_AR_EN.pptx")
    prs.save(docs_path)
    print(f"[+] تم إنشاء العرض التقديمي في المشروع: {docs_path}")

    desktop_dir = r"C:\Users\lenovo\Desktop\AI_Web_Vulnerability_Graduation_Project"
    os.makedirs(desktop_dir, exist_ok=True)
    desktop_path = os.path.join(desktop_dir, "Graduation_Project_Presentation_AR_EN.pptx")
    shutil.copy2(docs_path, desktop_path)
    print(f"[+] تم نسخ العرض التقديمي إلى سطح المكتب: {desktop_path}")


if __name__ == "__main__":
    create_presentation()

