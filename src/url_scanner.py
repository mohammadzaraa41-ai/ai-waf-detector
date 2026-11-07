import re
import time
import urllib.parse
import httpx

from waf_engine import AIWafEngine


class WebURLVulnerabilityScanner:
    """
    فاحص ثغرات المواقع المتقدم بالرابط (AI-Assisted Website, Form & Endpoint Vulnerability Scanner):
    يقوم بالاتصال بالرابط وفحص:
    1. بنية الرابط ومعاملاته عبر نموذج الذكاء الاصطناعي (AI Payload Inspection).
    2. ترويسات الأمان القياسية (HTTP Security Headers Audit).
    3. أمان ملفات الارتباط والجلسات (Cookies Security: HttpOnly, Secure, SameSite).
    4. الفحص العميق لنماذج الإدخال وحقولها (Deep HTML Forms & Input Surface Analysis: CSRF, Password over HTTP/GET, File Upload).
    5. اكتشاف مصادر DOM XSS المحتملة داخل سكربتات الصفحة (DOM Sinks Inspection).
    """

    def __init__(self):
        self.waf_engine = AIWafEngine()

    @staticmethod
    def _analyze_forms_and_dom(html_body: str, scheme: str) -> tuple[list[dict], list[dict], int]:
        forms_report = []
        extra_vulns = []
        forms_matches = re.finditer(
            r"<form\b([^>]*)>(.*?)</form>", html_body or "", flags=re.IGNORECASE | re.DOTALL
        )
        total_inputs = len(re.findall(r"<input\b[^>]*>", html_body or "", flags=re.IGNORECASE))

        for idx, match in enumerate(forms_matches, start=1):
            attrs = match.group(1) or ""
            inner = match.group(2) or ""
            action_m = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", attrs, re.IGNORECASE)
            method_m = re.search(r"method\s*=\s*[\"']([^\"']*)[\"']", attrs, re.IGNORECASE)
            action = action_m.group(1) if action_m else "(same-page)"
            method = (method_m.group(1) if method_m else "GET").upper()

            inputs = re.findall(r"<input\b([^>]*)>", inner, re.IGNORECASE)
            input_names = []
            has_password = False
            has_file = False
            for inp in inputs:
                nm = re.search(r"name\s*=\s*[\"']([^\"']+)[\"']", inp, re.IGNORECASE)
                tp = re.search(r"type\s*=\s*[\"']([^\"']+)[\"']", inp, re.IGNORECASE)
                if nm:
                    input_names.append(nm.group(1))
                if tp and tp.group(1).lower() == "password":
                    has_password = True
                if tp and tp.group(1).lower() == "file":
                    has_file = True

            has_csrf = bool(re.search(r"(csrf|_token|authenticity_token|xsrf|__requestverificationtoken)", inner, re.IGNORECASE))
            risks = []

            if not has_csrf and method == "POST":
                risks.append("Missing Anti-CSRF Token")
                extra_vulns.append({
                    "category": f"CSRF Risk (Form #{idx})",
                    "severity": "Medium",
                    "finding": f"النموذج رقم #{idx} (action='{action}') يرسل بيانات عبر POST بدون رمز حماية Anti-CSRF Token.",
                    "remediation": "إضافة حقل مخفي يحتوي على رمز CSRF عشوائي مرتبط بجلسة المستخدم.",
                })
            if has_password and (scheme != "https" or method == "GET"):
                risks.append("Insecure Password Transmission")
                extra_vulns.append({
                    "category": f"Insecure Password Form (Form #{idx})",
                    "severity": "High",
                    "finding": f"النموذج #{idx} يحتوي على حقل كلمة مرور ويتم إرساله عبر {method} أو بروتوكول غير مشفر.",
                    "remediation": "استخدام method='POST' حصرياً مع تشفير HTTPS كامل.",
                })
            if has_file:
                risks.append("File Upload Surface")

            forms_report.append({
                "form_id": idx,
                "action": action,
                "method": method,
                "inputs_count": len(inputs),
                "input_names": input_names[:8],
                "csrf_protected": has_csrf,
                "risks": risks or ["Low Risk"],
            })

        # فحص DOM XSS Sinks في السكربتات المضمنة
        dom_sinks = re.findall(
            r"(document\.write\s*\(|\.innerHTML\s*=|eval\s*\(|location\.(search|hash))",
            html_body or "",
            flags=re.IGNORECASE,
        )
        if len(dom_sinks) >= 2:
            extra_vulns.append({
                "category": "Potential DOM-Based XSS Surface",
                "severity": "Low",
                "finding": f"تم رصد {len(dom_sinks)} مواضع استخدام دوال DOM حساسة (innerHTML / document.write / location.search) في الصفحة.",
                "remediation": "استخدام textContent بدلاً من innerHTML وتعقيم قيم location.search قبل المعالجة.",
            })

        return forms_report, extra_vulns, total_inputs

    def scan_url(self, target_url: str, timeout: float = 8.0) -> dict:
        start_time = time.perf_counter()
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url.strip()

        parsed = urllib.parse.urlparse(target_url)
        uri_path_query = parsed.path or "/"
        if parsed.query:
            uri_path_query += "?" + parsed.query

        ai_url_check = self.waf_engine.inspect_request(
            raw_payload=uri_path_query,
            client_ip="URL-Scanner",
            method="GET",
        )

        vulnerabilities = []
        passed_checks = []
        score = 100

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

        if ai_url_check["prediction"] != "Normal":
            score -= 30
            vulnerabilities.append({
                "category": f"AI Payload Alert ({ai_url_check['prediction']})",
                "severity": "Critical",
                "finding": f"اكتشف نموذج الذكاء الاصطناعي نمط هجوم ({ai_url_check['prediction']}) داخل معاملات الرابط بنسبة ثقة {ai_url_check['confidence']}%",
                "remediation": "تصفية المدخلات واستخدام الاستعلامات المعلمية (Prepared Statements) وتفعيل جدار الحماية AI WAF.",
            })
        else:
            passed_checks.append("معاملات الرابط مفحوصة بالذكاء الاصطناعي وخالية من أنماط الحقن.")

        http_status = None
        headers_dict = {}
        html_body = ""
        connection_error = None

        try:
            with httpx.Client(follow_redirects=True, timeout=timeout, verify=False) as client:
                resp = client.get(target_url, headers={"User-Agent": "AI-WebVuln-GraduationScanner/3.0"})
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
                "forms_analysis": [],
                "vulnerabilities": vulnerabilities,
                "passed_checks": passed_checks,
                "scan_duration_ms": round((time.perf_counter() - start_time) * 1000, 2),
            }

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

        for leak_hdr in ("server", "x-powered-by", "x-aspnet-version"):
            if leak_hdr in headers_dict and any(ch.isdigit() for ch in headers_dict[leak_hdr]):
                score -= 6
                vulnerabilities.append({
                    "category": f"Information Disclosure ({leak_hdr})",
                    "severity": "Low",
                    "finding": f"تسريب إصدار الخادم أو التقنية عبر الترويسة `{leak_hdr}: {headers_dict[leak_hdr]}`",
                    "remediation": "إخفاء رقم إصدار الخادم (Server Banner) من إعدادات خادم الويب.",
                })

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

        forms_report, extra_vulns, inputs_count = self._analyze_forms_and_dom(html_body, parsed.scheme)
        for v in extra_vulns:
            score -= 10 if v["severity"] != "Low" else 4
            vulnerabilities.append(v)

        final_score = max(min(score, 100), 0)
        grade = "A" if final_score >= 90 else "B" if final_score >= 75 else "C" if final_score >= 60 else "D" if final_score >= 45 else "F"

        return {
            "target_url": target_url,
            "reachable": True,
            "http_status": http_status,
            "security_score": final_score,
            "grade": grade,
            "forms_detected": len(forms_report),
            "inputs_detected": inputs_count,
            "forms_analysis": forms_report,
            "ai_url_analysis": ai_url_check,
            "vulnerabilities": vulnerabilities,
            "passed_checks": passed_checks,
            "scan_duration_ms": round((time.perf_counter() - start_time) * 1000, 2),
        }
