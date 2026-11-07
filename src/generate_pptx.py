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

    footer = slide.shapes.add_textbox(Inches(0.5), Inches(7.0), Inches(12.3), Inches(0.4))
    ftf = footer.text_frame
    fp = ftf.paragraphs[0]
    fp.text = f"Graduation Project Defense | SentinelWAF v3.0 — AI Web Vulnerability, WAF & SAST Platform  —  Slide {slide_num}/10"
    fp.font.size = Pt(10)
    fp.font.color.rgb = MUTED_TEXT
    fp.font.name = "Arial"


def add_two_column_cards(slide, en_title, en_bullets, ar_title, ar_bullets):
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

    # Slide 1: Cover Slide
    s1 = prs.slides.add_slide(blank_layout)
    bg1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg1.fill.solid()
    bg1.fill.fore_color.rgb = NAVY
    bg1.line.fill.background()

    tb1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.5), Inches(11.333), Inches(4.8))
    tf1 = tb1.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "مشروع التخرج (Graduation Project — SentinelWAF v3.0)"
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
    p3.text = "AI-Powered Web Vulnerability Discovery, Smart WAF & SAST Platform"
    p3.font.size = Pt(22)
    p3.font.bold = True
    p3.font.color.rgb = RGBColor(96, 165, 250)
    p3.font.name = "Arial"
    p3.alignment = PP_ALIGN.CENTER
    p3.space_before = Pt(12)

    p4 = tf1.add_paragraph()
    p4.text = "1. Real-ML HTTP WAF  |  2. Deep URL & HTML Form Scanner (DAST)  |  3. AI Source Code Scanner (SAST)"
    p4.font.size = Pt(14)
    p4.font.color.rgb = RGBColor(203, 213, 225)
    p4.font.name = "Arial"
    p4.alignment = PP_ALIGN.CENTER
    p4.space_before = Pt(28)

    # Slide 2: Problem Statement & Motivation
    s2 = prs.slides.add_slide(blank_layout)
    add_header_banner(s2, prs, "1. Problem Statement & 3-Pillar Objective", "1. مشكلة البحث وأهداف المنصة الثلاثية", 2)
    add_two_column_cards(
        s2,
        "Why Traditional Rule-Based WAFs Fail",
        [
            "Web apps face daily SQLi, XSS, LFI, RCE, and CSRF attacks across traffic, forms, and backend code.",
            "Static Regex Firewalls (ModSecurity) suffer from High False Positives on developer/user queries.",
            "Legitimate queries like '/search?q=select best laptop and update windows' get wrongly blocked.",
            "Attackers bypass static rules via Triple URL Encoding (%252f) and comment-split SQLi (UnIoN/**/SeLeCt).",
            "Our Solution: A 3-pillar platform combining Real-ML WAF + Deep Form Auditor + AI Source Code SAST."
        ],
        "لماذا نحتاج إلى منصة ذكاء اصطناعي ثلاثية الأبعاد؟",
        [
            "تتعرض تطبيقات الويب لثغرات في كلٍ من: طلبات HTTP، نماذج HTML، والكود المصدري الخلفي.",
            "الأنظمة التقليدية تعاني من ارتفاع الإنذارات الكاذبة (False Positives) عند وجود كلمات تقنية عادية.",
            "سهولة تجاوز القواعد الثابتة عبر التشفير المزدوج/الثلاثي والتعليقات المموهة.",
            "الحل المبتكر (SentinelWAF v3.0): دمج 3 محركات ذكية في منصة واحدة:",
            "(1) جدار حماية بالذكاء الاصطناعي (WAF) + (2) فاحص نماذج وترويسات المواقع + (3) فاحص الكود المصدري (SAST)."
        ]
    )

    # Slide 3: 4-Week Execution Roadmap
    s3 = prs.slides.add_slide(blank_layout)
    add_header_banner(s3, prs, "2. Project 4-Week Execution Plan", "2. الخطة الزمنية لتنفيذ المشروع (4 أسابيع)", 3)
    add_slide_table(
        s3,
        ["Week / الأسبوع", "Phase / المرحلة", "Key Tasks / المهام المنفذة", "Deliverables / المخرجات"],
        [
            ["Week 1\nالأسبوع الأول", "Problem & Architecture\nالمشكلة والمعمارية", "Analyze OWASP Top 10 & Rule-Based WAF flaws; design 3-pillar AI architecture.", "Week 1 Report + System Architecture"],
            ["Week 2\nالأسبوع الثاني", "Expanded Dataset (1,543)\nالبيانات واستخراج الخصائص", "Build 1,543 unique requests (with Hard Negatives & Zero-Day); 3x URL Decoding, Entropy, Char N-Grams.", "http_requests.csv + preprocess.py"],
            ["Week 3\nالأسبوع الثالث", "AI Training & Cloud Weights\nالتدريب وتصدير الأوزان", "Train & compare LogReg, RF, Deep MLP (99.75% acc, 0% FP); export 16.8KB real weights to cloud.", "train.py + model_weights.json"],
            ["Week 4\nالأسبوع الرابع", "WAF + Form Audit + SAST\nجدار الحماية وفاحص الكود", "FastAPI WAF, Deep HTML Form Scanner, AI Source Code SAST Scanner, and Vercel Cloud Console.", "url_scanner.py + code_scanner.py + index.html"],
        ]
    )

    # Slide 4: Literature Review Comparison
    s4 = prs.slides.add_slide(blank_layout)
    add_header_banner(s4, prs, "3. Comparison with Existing Solutions", "3. مقارنة النظام المقترح بالدراسات والأنظمة السابقة", 4)
    add_slide_table(
        s4,
        ["Criterion / المعيار", "Rule-Based WAF (ModSecurity)", "Word-Level ML (Classic TF-IDF)", "SentinelWAF v3.0 (مشروعنا المطور)"],
        [
            ["Inspection Granularity\nمستوى الفحص", "Static Regular Expressions (Regex)", "Space-separated words", "Char N-Grams (2-5) + 9 Contextual Features + Deep MLP"],
            ["Obfuscation Resistance\nمقاومة التشفير والتمويه", "Low (ضعيفة أمام التشفير المتعدد)", "Medium (متوسطة)", "Very High (فك تشفير ثلاثي + عشوائية شانون)"],
            ["False Positive Rate\nمعدل الإنذارات الكاذبة", "High (مرتفع مع الكلمات التقنية)", "Moderate (متوسط)", "0.00% on Holdout Benign Traffic (124/124)"],
            ["Deep HTML Form Audit\nفحص نماذج الإدخال", "Not Supported (غير مدعوم)", "Not Supported (غير مدعوم)", "Extracts <form>/<input>, CSRF tokens & DOM XSS sinks"],
            ["Source Code SAST\nفحص الكود المصدري", "Not Supported (غير مدعوم)", "Not Supported (غير مدعوم)", "Line-by-Line Python/PHP/JS SAST + Automated Patch"],
        ]
    )

    # Slide 5: Hybrid Architecture & Feature Engineering
    s5 = prs.slides.add_slide(blank_layout)
    add_header_banner(s5, prs, "4. Hybrid AI Architecture & Real Cloud Weights", "4. المعمارية الهجينة وتصدير الأوزان الرياضية للسحابة", 5)
    add_two_column_cards(
        s5,
        "Hybrid Processing & Serverless ML (preprocess.py & scan.py)",
        [
            "Step 1: 3-Layer Recursive URL Decoding & Normalization.",
            "Step 2: Character N-Grams TF-IDF (2 to 5 chars) to capture sub-word obfuscated payloads.",
            "Step 3: Shannon Entropy H(X) & Contextual Syntactic Indicators.",
            "Step 4: Deep MLP (128×64) local model + Exported Cloud Weight Matrix (api/model_weights.json, 16.8 KB).",
            "Step 5: Executes genuine matrix forward-pass (W·x + b -> Softmax) on Vercel in < 2.5 ms."
        ],
        "خط أنابيب المعالجة والاستدلال الرياضي الحقيقي",
        [
            "1. فك التشفير الثلاثي (3x URL Decoding) لإحباط التمويه المتعدد.",
            "2. استخراج مقاطع الأحرف (Char N-Grams) لالتقاط الهجمات المتصلة بدون مسافات.",
            "3. حساب عشوائية النص (Shannon Entropy) والمؤشرات السياقية الذكية.",
            "4. تصدير أوزان النموذج الفعلية إلى ملف سحابي خفيف (api/model_weights.json بحجم 16.8 KB).",
            "5. تنفيذ الضرب المصفوفي ودالة Softmax الحقيقية على سحابة Vercel في أقل من 2.5 ملي ثانية."
        ]
    )

    # Slide 6: Expanded Dataset Construction (1,543 Unique Samples)
    s6 = prs.slides.add_slide(blank_layout)
    add_header_banner(s6, prs, "5. Expanded Dataset (1,543 Samples) & Zero-Day Holdout", "5. قاعدة البيانات الموسعة (1,543 عينة) واختبار Zero-Day", 6)
    add_two_column_cards(
        s6,
        "1,543 Unique Requests + Unseen Zero-Day Split",
        [
            "Normal (481 samples, 31.2%): Standard traffic + Developer Forum Hard Negatives discussing SQL/Linux/JS safely.",
            "SQL Injection - SQLi (360 samples, 23.3%): Union, blind (pg_sleep/WAITFOR), hex (0x...), and comment-split (UnIoN/**/SeLeCt).",
            "Path & Command Attack (352 samples, 22.8%): ..%252f..%252fetc/passwd, php://filter, and shell chaining (; cat, | whoami).",
            "Cross-Site Scripting - XSS (350 samples, 22.7%): Polyglots, SVG/MathML, event handlers, and DOM sinks."
        ],
        "توزيع قاعدة البيانات الموسعة (1,543 طلب فريد)",
        [
            "طلبات طبيعية Normal (481 عينة - 31.2%): تشمل استعلامات مطورين خادعة (Hard Negatives) لاختبار عدم حدوث إنذارات كاذبة.",
            "حقن قواعد البيانات SQLi (360 عينة - 23.3%): هجمات مباشرة، عمياء زمنية، ومموهة بالتعليقات والترميز الست عشري.",
            "اختراق المسارات والأوامر Path & Cmd (352 عينة - 22.8%): قفز المسارات المزدوج ومرشحات PHP وحقن الأوامر.",
            "البرمجة عبر المواقع XSS (350 عينة - 22.7%): أنماط Polyglot ووسوم SVG ومعالجات الأحداث."
        ]
    )

    # Slide 7: AI Models Training & Evaluation
    s7 = prs.slides.add_slide(blank_layout)
    add_header_banner(s7, prs, "6. AI Models Evaluation on Holdout + Zero-Day Split (N = 394)", "6. تقييم ومقارنة نماذج الذكاء الاصطناعي ومصفوفة الالتباس", 7)
    add_slide_table(
        s7,
        ["AI Model / النموذج", "Architecture / البنية", "Accuracy", "Macro Precision", "Macro Recall", "Macro F1", "Normal FP Rate"],
        [
            ["Deep MLP (Primary Model)", "Neural Network (128 × 64)", "0.9975", "0.9973", "0.9972", "0.9972", "0.00% (0/124)"],
            ["Random Forest", "Ensemble (100 Trees)", "0.9975", "0.9972", "0.9980", "0.9976", "0.81% (1/124)"],
            ["Logistic Regression", "L2 Linear Baseline", "0.9898", "0.9904", "0.9896", "0.9900", "0.81% (1/124)"],
        ],
        top_in=1.7,
        height_in=2.6
    )
    tb7 = s7.shapes.add_textbox(Inches(0.5), Inches(4.55), Inches(12.3), Inches(2.2))
    tf7 = tb7.text_frame
    tf7.word_wrap = True
    p7 = tf7.paragraphs[0]
    p7.text = "تحليل مصفوفة الالتباس (Confusion Matrix) على عينة الاختبار (394 عينة):"
    p7.font.size = Pt(16)
    p7.font.bold = True
    p7.font.color.rgb = NAVY
    p7.alignment = PP_ALIGN.RIGHT

    p7_b = tf7.add_paragraph()
    p7_b.text = "• صنف نموذج Deep MLP جميع الطلبات الطبيعية (124 من 124) بشكل صحيح تماماً (0.00% إنذارات كاذبة)، وجميع هجمات SQLi (91/91) و Path/Cmd (90/90) بدقة 100%.\n• تفوقت الشبكة العصبية والغابات العشوائية (99.75%) على نموذج الانحدار اللوجستي الخطي (98.98%) في كشف هجمات Zero-Day المموهة."
    p7_b.font.size = Pt(14)
    p7_b.font.color.rgb = DARK_TEXT
    p7_b.alignment = PP_ALIGN.RIGHT
    p7_b.space_before = Pt(6)

    # Slide 8: Live WAF Middleware Benchmarks
    s8 = prs.slides.add_slide(blank_layout)
    add_header_banner(s8, prs, "7. Live FastAPI WAF & Cloud Weights Benchmark", "7. نتائج الاختبار الحي لجدار الحماية والأوزان السحابية", 8)
    add_slide_table(
        s8,
        ["Scenario / السيناريو", "Tested URI / الرابط المختبر", "HTTP Status", "WAF Action", "Confidence", "Latency"],
        [
            ["Normal Search (Trap)", "/search?q=select+best+laptop+and+update+windows&page=1", "200 OK", "ALLOWED", "99.93%", "2.31 ms"],
            ["Normal Product View", "/products?id=405&cat=electronics", "200 OK", "ALLOWED", "99.98%", "1.89 ms"],
            ["Union SQL Injection", "/products?id=10' UNION SELECT username,password FROM users--", "403 Forbidden", "BLOCKED (SQLi)", "99.99%", "2.18 ms"],
            ["Comment-Split SQLi", "/api/v1/user?id=42' UnIoN/**/aLl/**/SeLeCt 1,user(),3--", "403 Forbidden", "BLOCKED (SQLi)", "99.96%", "2.45 ms"],
            ["Reflected XSS", "/search?q=<script>alert(document.cookie)</script>", "403 Forbidden", "BLOCKED (XSS)", "99.97%", "2.36 ms"],
            ["Encoded SVG XSS", "/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E", "403 Forbidden", "BLOCKED (XSS)", "99.94%", "2.08 ms"],
            ["Double-Encoded LFI", "/download?file=..%252f..%252f..%252fetc%252fpasswd", "403 Forbidden", "BLOCKED (Path)", "99.98%", "2.04 ms"],
            ["OS Command Injection", "/ping?host=127.0.0.1;cat /etc/shadow", "403 Forbidden", "BLOCKED (Cmd)", "99.97%", "1.91 ms"],
        ]
    )

    # Slide 9: Deep URL Form Scanner & AI SAST Code Scanner
    s9 = prs.slides.add_slide(blank_layout)
    add_header_banner(s9, prs, "8. Deep URL Form Scanner & AI Source Code SAST", "8. فاحص نماذج المواقع وفاحص الكود المصدري بالذكاء الاصطناعي (SAST)", 9)
    add_two_column_cards(
        s9,
        "Deep URL & Form Scanner + AI SAST Engine",
        [
            "1. Deep URL & HTML Form Scanner (url_scanner.py):",
            "   • Audits HTTPS/TLS, CSP, HSTS, X-Frame-Options, and Cookie HttpOnly flags.",
            "   • Parses <form> and <input> tags to detect missing Anti-CSRF tokens and DOM XSS sinks.",
            "2. AI Source Code Vulnerability Scanner - SAST (code_scanner.py):",
            "   • Scans Python, PHP, and Node.js code line-by-line for CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (RCE), CWE-22 (LFI), and CWE-798 (Hardcoded Secrets) with automated secure patches."
        ],
        "فاحص النماذج الحية + محرك فحص الكود المصدري (SAST)",
        [
            "1. الفاحص العميق للمواقع ونماذج الإدخال (url_scanner.py):",
            "   • يفحص تشفير HTTPS وترويسات الأمان (CSP, HSTS, X-Frame-Options) وأمان الكوكيز.",
            "   • يستخرج جميع نماذج <form> وحقول <input> لكشف غياب رموز Anti-CSRF وثغرات DOM XSS.",
            "2. فاحص الكود المصدري بالذكاء الاصطناعي (code_scanner.py - SAST):",
            "   • يحلل أكواد Python و PHP و Node.js سطراً بسطر، ويحدد رقم السطر المصاب وتصنيف CWE/OWASP ويولد الكود الآمن البديل (Secure Patch) فوراً."
        ]
    )

    # Slide 10: Conclusion & Future Work
    s10 = prs.slides.add_slide(blank_layout)
    add_header_banner(s10, prs, "9. Conclusion & Future Work", "9. الخاتمة والتوصيات المستقبلية", 10)
    add_two_column_cards(
        s10,
        "Conclusion & Key Achievements",
        [
            "Delivered SentinelWAF v3.0: an integrated AI WAF, Deep URL/Form Scanner, and SAST Source Code Auditor.",
            "Achieved 99.75% accuracy and 0.00% False Positives on a 1,543-sample dataset with unseen Zero-Day holdout tests.",
            "Exported real trained ML weights (16.8 KB) to Vercel Serverless for < 2.5 ms cloud inference.",
            "Future Work: Transformer fine-tuning (SecBERT/CodeBERT) for multi-file AST taint tracking."
        ],
        "الخاتمة وأبرز الإنجازات",
        [
            "تم تطوير منصة SentinelWAF v3.0 المتكاملة (جدار حماية ذكي + فاحص مواقع ونماذج + فاحص كود مصدري SAST).",
            "تحقيق دقة 99.75% وصفر بالمئة (0.00%) إنذارات كاذبة على قاعدة بيانات موسعة تضم 1,543 طلباً واختبارات Zero-Day.",
            "تصدير أوزان الذكاء الاصطناعي الحقيقية للعمل على سحابة Vercel بزمن استجابة أقل من 2.5 ملي ثانية.",
            "مستقبلاً: دمج نماذج CodeBERT لتحليل شجرة الكود (AST) عبر الملفات المتعددة."
        ]
    )

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docs_path = os.path.join(base_dir, "docs", "Graduation_Project_Presentation_AR_EN.pptx")
    prs.save(docs_path)
    print(f"[+] تم تحديث العرض التقديمي في المشروع: {docs_path}")

    desktop_dir = r"C:\Users\lenovo\Desktop\AI_Web_Vulnerability_Graduation_Project"
    os.makedirs(desktop_dir, exist_ok=True)
    desktop_path = os.path.join(desktop_dir, "Graduation_Project_Presentation_AR_EN.pptx")
    try:
        shutil.copy2(docs_path, desktop_path)
    except PermissionError:
        desktop_path = os.path.join(desktop_dir, "Graduation_Project_Presentation_AR_EN_v3.0.pptx")
        shutil.copy2(docs_path, desktop_path)
    print(f"[+] تم نسخ العرض التقديمي المحدث إلى سطح المكتب: {desktop_path}")


if __name__ == "__main__":
    create_presentation()
