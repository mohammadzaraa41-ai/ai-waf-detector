from fastapi.testclient import TestClient
from waf_server import app

client = TestClient(app)


def run_live_waf_simulation():
    """
    محاكاة إرسال طلبات حقيقية (طبيعية وهجومية) إلى خادم الويب المحمي بـ AI WAF
    للتحقق من الحجب التلقائي (403 Forbidden) والسماح بالطلبات السليمة (200 OK).
    """
    scenarios = [
        ("طلب بحث طبيعي (مع كلمات خادعة)", "/search?q=select+best+laptop+and+update+windows&page=1", 200),
        ("تصفح منتج طبيعي", "/products?id=405&cat=electronics", 200),
        ("تحميل ملف طبيعي", "/download?file=graduation_thesis_plan.pdf", 200),
        ("هجوم SQL Injection (استخراج بيانات)", "/products?id=10' UNION SELECT username,password FROM users--", 403),
        ("هجوم Blind SQLi (تأخير زمني)", "/search?q=test' AND SLEEP(5)--", 403),
        ("هجوم XSS (سرقة الجلسة)", "/search?q=<script>alert(document.cookie)</script>", 403),
        ("هجوم XSS مشفر (Encoded SVG)", "/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E", 403),
        ("هجوم اختراق المسارات (Path Traversal)", "/download?file=../../../../etc/passwd", 403),
        ("هجوم حقن أوامر النظام (Command Injection)", "/ping?host=127.0.0.1;cat /etc/shadow", 403),
    ]

    print("=" * 75)
    print("بدء اختبار جدار الحماية التطبيقي الحي (AI WAF Middleware Live Test)")
    print("=" * 75)

    passed = 0
    for title, uri, expected_status in scenarios:
        response = client.get(uri)
        actual_status = response.status_code
        waf_action = response.headers.get("X-AI-WAF-Action", "UNKNOWN")
        is_ok = actual_status == expected_status
        if is_ok:
            passed += 1

        status_icon = "✅" if is_ok else "❌"
        print(f"{status_icon} السيناريو: {title}")
        print(f"   الرابط   : {uri}")
        print(f"   الحالة   : HTTP {actual_status} | قرار الجدار: {waf_action}")
        if actual_status == 403:
            body = response.json()
            print(f"   التهديد  : {body['threat_detected']} (ثقة: {body['confidence']} | زمن الفحص: {body['inspection_latency_ms']} ms)")
        else:
            latency = response.headers.get("X-AI-WAF-Latency-Ms", "-")
            print(f"   الاستجابة: تم السماح بالمرور للخادم بنجاح (زمن الفحص: {latency} ms)")
        print("-" * 75)

    print(f"\n[+] نتيجة اختبار جدار الحماية: نجاح {passed} من أصل {len(scenarios)} سيناريو بنسبة {(passed/len(scenarios))*100:.1f}%")


if __name__ == "__main__":
    run_live_waf_simulation()

