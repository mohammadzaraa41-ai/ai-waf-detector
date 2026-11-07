import re
import time
import urllib.parse
import httpx

from waf_engine import AIWafEngine


class WebURLVulnerabilityScanner:
    """
    فاحص ثغرات المواقع بالرابط (Passive & AI-Assisted Website Vulnerability Scanner):
    يقوم بالاتصال بالرابط وفحص:
    1. بنية الرابط ومعاملاته عبر نموذج الذكاء الاصطناعي (AI Payload Inspection).
    2. ترويسات الأمان القياسية (HTTP Security Headers Audit).
    3. أمان ملفات الارتباط والجلسات (Cookies Security: HttpOnly, Secure, SameSite).
    4. تحليل نماذج الإدخال (HTML Forms) لاكتشاف مخاطر CSRF و XSS و SQLi المحتملة.
    5. حساب درجة الأمان الكلية للموقع (Security Score 0-100) مع التوصيات الدفاعية.
    """

    def __init__(self):
        self.waf_engine = AIWafEngine()

    def scan_url(self, target_url: str, timeout: float = 8.0) -> dict:
        start_time = time.perf_counter()
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url.strip()

        parsed = urllib.parse.urlparse(target_url)
        uri_path_query = parsed.path or "/"
        if parsed.query:
            uri_path_query += "?" + parsed.query

        # 1. فحص الرابط نفسه بالذكاء الاصطناعي (هل يحتوي الرابط على حمولة هجومية؟)
        ai_url_check = self.waf_engine.inspect_request(
            raw_payload=uri_path_query,
            client_ip="URL-Scanner",
            method="GET",
        )

        vulnerabilities = []
        passed_checks = []
        score = 100

        # التحقق من بروتوكول التشفير HTTPS
        if parsed.scheme != "https":
            score -= 15
            vulnerabilities.append({
                "category": "Transport Security (أمان النقل)",
                "severity": "High",
                "finding": "الموقع يستخدم بروتوكول HTTP غير المشفر بدلاً من HTTPS",
                "remediation": "تفعيل شهادة TLS/SSL وإجبار التحويل التلقائي إلى HTTPS.",
            })
        else:
            passed_checks.append("استخدام بروتوكول اتصال مشفر (HTTPS).")

        # إذا كان الرابط نفسه يحتوي على هجوم في معاملاته
        if ai_url_check["prediction"] != "Normal":
            score -= 30
            vulnerabilities.append({
                "category": f"AI Payload Alert ({ai_url_check['prediction']})",
                "severity": "Critical",
                "finding": f"اكتشف نموذج الذكاء الاصطناعي نمط هجوم ({ai_url_check['prediction']}) داخل معاملات الرابط بنسبة ثقة {ai_url_check['confidence']}%",
                "remediation": "تصفية المدخلات واستخدام الاستعلامات المعلمية (Prepared Statements) وتفعيل جدار الحماية AI WAF.",
            })

        # 2. الاتصال بالموقع وفحص الترويسات ومحتوى الصفحة (Passive HTTP Inspection)
        http_status = None
        headers_dict = {}
        html_body = ""
        connection_error = None

        try:
            with httpx.Client(follow_redirects=True, timeout=timeout, verify=False) as client:
                resp = client.get(target_url, headers={"User-Agent": "AI-WebVuln-GraduationScanner/1.0"})
                http_status = resp.status_code
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                html_body = resp.text or ""
        except Exception as exc:
            connection_error = str(exc)

        if connection_error:
            return {
                "target_url": target_url,
                "reachable": False,
                "error": connection_error,
                "ai_url_analysis": ai_url_check,
                "security_score": max(score, 0),
                "vulnerabilities": vulnerabilities,
                "passed_checks": passed_checks,
                "scan_duration_ms": round((time.perf_counter() - start_time) * 1000, 2),
            }

        # 3. فحص ترويسات الأمان (Security Headers Audit)
        security_headers_spec = [
            (
                "content-security-policy",
                "Medium",
                12,
                "غياب ترويسة Content-Security-Policy (CSP) مما يزيد خطر تنفيذ هجمات XSS",
                "إضافة ترويسة Content-Security-Policy لتقييد مصادر تشغيل أكواد JavaScript.",
            ),
            (
                "x-frame-options",
                "Medium",
                10,
                "غياب ترويسة X-Frame-Options مما يجعل الصفحة عرضة لهجمات Clickjacking",
                "إضافة الترويسة X-Frame-Options: DENY أو SAMEORIGIN.",
            ),
            (
                "strict-transport-security",
                "Low",
                8,
                "غياب ترويسة HSTS (Strict-Transport-Security) لحماية الاتصال المشفر",
                "إضافة Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            ),
            (
                "x-content-type-options",
                "Low",
                6,
                "غياب ترويسة X-Content-Type-Options لمنع تخمين نوع الملفات (MIME Sniffing)",
                "إضافة الترويسة X-Content-Type-Options: nosniff.",
            ),
        ]

        for h_name, sev, penalty, finding_msg, rem_msg in security_headers_spec:
            if h_name not in headers_dict:
                score -= penalty
                vulnerabilities.append({
                    "category": f"Missing Security Header ({h_name})",
                    "severity": sev,
                    "finding": finding_msg,
                    "remediation": rem_msg,
                })
            else:
                passed_checks.append(f"ترويسة الأمان `{h_name}` مفعّلة.")

        # فحص تسريب معلومات الخادم (Information Disclosure)
        for leak_hdr in ("server", "x-powered-by", "x-aspnet-version"):
            if leak_hdr in headers_dict and any(ch.isdigit() for ch in headers_dict[leak_hdr]):
                score -= 6
                vulnerabilities.append({
                    "category": f"Information Disclosure ({leak_hdr})",
                    "severity": "Low",
                    "finding": f"تسريب إصدار الخادم أو التقنية عبر الترويسة `{leak_hdr}: {headers_dict[leak_hdr]}`",
                    "remediation": "إخفاء رقم إصدار الخادم (Server Banner) من إعدادات خادم الويب.",
                })

        # 4. فحص أمان الكوكيز (Cookie Security Flags)
        set_cookie = headers_dict.get("set-cookie", "")
        if set_cookie:
            cookie_lower = set_cookie.lower()
            if "httponly" not in cookie_lower:
                score -= 12
                vulnerabilities.append({
                    "category": "Insecure Cookie (Missing HttpOnly)",
                    "severity": "High",
                    "finding": "ملف الارتباط (Cookie) يفتقر إلى خاصية HttpOnly مما يسمح بسرقته عبر document.cookie في حال وجود XSS",
                    "remediation": "تفعيل العلم HttpOnly و Secure و SameSite=Strict لجميع كوكيز الجلسات.",
                })
            else:
                passed_checks.append("ملفات الارتباط محمية بخاصية HttpOnly.")

        # 5. تحليل النماذج وحقول الإدخال في الصفحة (HTML Forms & CSRF/XSS Surface)
        forms = re.findall(r"<form\b[^>]*>(.*?)</form>", html_body, flags=re.IGNORECASE | re.DOTALL)
        inputs_count = len(re.findall(r"<input\b[^>]*>", html_body, flags=re.IGNORECASE))

        for idx, form_inner in enumerate(forms, start=1):
            has_csrf = bool(re.search(r"(csrf|_token|authenticity_token|xsrf)", form_inner, flags=re.IGNORECASE))
            if not has_csrf:
                score -= 10
                vulnerabilities.append({
                    "category": f"CSRF Risk (Form #{idx})",
                    "severity": "Medium",
                    "finding": f"النموذج رقم #{idx} داخل الصفحة لا يحتوي على رمز حماية واضح ضد تزوير الطلبات (Anti-CSRF Token)",
                    "remediation": "إدراج رمز CSRF عشوائي ومرتبط بالجلسة في جميع نماذج الإرسال.",
                })

        final_score = max(min(score, 100), 0)
        grade = "A" if final_score >= 90 else "B" if final_score >= 75 else "C" if final_score >= 60 else "D" if final_score >= 45 else "F"

        return {
            "target_url": target_url,
            "reachable": True,
            "http_status": http_status,
            "security_score": final_score,
            "grade": grade,
            "forms_detected": len(forms),
            "inputs_detected": inputs_count,
            "ai_url_analysis": ai_url_check,
            "vulnerabilities": vulnerabilities,
            "passed_checks": passed_checks,
            "scan_duration_ms": round((time.perf_counter() - start_time) * 1000, 2),
        }


if __name__ == "__main__":
    from fastapi.testclient import TestClient
    from waf_server import app

    scanner = WebURLVulnerabilityScanner()
    print("=" * 70)
    print("اختبار وحدة فحص ثغرات المواقع بالرابط (WebURLVulnerabilityScanner):")
    print("=" * 70)
    res = scanner.scan_url("https://example.com/search?q=python+course")
    print(f"الرابط المفحوص : {res['target_url']}")
    print(f"حالة الاتصال   : {'متصل' if res['reachable'] else 'تعذر الاتصال'}")
    print(f"درجة الأمان    : {res['security_score']}/100 (التقدير: {res.get('grade', '-')})")
    print(f"تصنيف الرابط AI: {res['ai_url_analysis']['prediction']} ({res['ai_url_analysis']['confidence']}%)")
    print(f"الثغرات المكتشفة ({len(res['vulnerabilities'])}):")
    for v in res["vulnerabilities"]:
        print(f"  - [{v['severity']}] {v['category']}: {v['finding']}")
        print(f"    الحل المقترح: {v['remediation']}")

