from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from waf_engine import AIWafEngine

app = FastAPI(
    title="AI-Powered Web Application Firewall (Smart WAF)",
    description="جدار حماية تطبيقات ويب يعتمد على الذكاء الاصطناعي لفحص الطلبات وحجب الهجمات في الوقت الفعلي.",
    version="1.0.0",
)

waf_engine = AIWafEngine()


@app.middleware("http")
async def ai_waf_middleware(request: Request, call_next):
    """
    الوسيط الأمني (WAF Middleware):
    يعترض كل طلب HTTP وارد قبل وصوله إلى الخادم الخلفي، ويفحص الرابط والمعاملات ومحتوى الطلب.
    """
    # استثناء صفحات التوثيق الخاصة بـ FastAPI
    if request.url.path in ("/docs", "/openapi.json", "/waf/stats"):
        return await call_next(request)

    # تجميع المسار + المعاملات (Query String) + جسم الطلب (إن وجد)
    full_uri = request.url.path
    if request.url.query:
        full_uri += "?" + request.url.query

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    combined_payload = f"{full_uri} {body_text}".strip()

    client_ip = request.client.host if request.client else "127.0.0.1"
    decision = waf_engine.inspect_request(
        raw_payload=combined_payload,
        client_ip=client_ip,
        method=request.method,
    )

    if decision["action"] == "BLOCKED":
        return JSONResponse(
            status_code=403,
            content={
                "status": "403 Forbidden - Blocked by AI WAF",
                "threat_detected": decision["prediction"],
                "confidence": f"{decision['confidence']}%",
                "inspection_latency_ms": decision["latency_ms"],
                "normalized_payload": decision["normalized_payload"],
                "message": "تم حجب هذا الطلب تلقائياً بواسطة نظام الذكاء الاصطناعي لاحتوائه على سلوك هجومي.",
            },
            headers={"X-AI-WAF-Action": "BLOCKED", "X-AI-WAF-Threat": decision["prediction"]},
        )

    response = await call_next(request)
    response.headers["X-AI-WAF-Action"] = "ALLOWED"
    response.headers["X-AI-WAF-Latency-Ms"] = str(decision["latency_ms"])
    return response


# =====================================================================
# نقاط النهاية المحمية (Protected Demo Web Application Endpoints)
# =====================================================================

@app.get("/")
def home():
    return {"status": "ok", "message": "مرحباً بك في تطبيق الويب المحمي بواسطة جدار الحماية الذكي (AI WAF)."}


@app.get("/search")
def search(q: str = "", page: int = 1):
    return {"status": "ok", "query": q, "page": page, "results": [f"Result 1 for {q}", f"Result 2 for {q}"]}


@app.get("/products")
def products(id: str = "1", cat: str = "general"):
    return {"status": "ok", "product_id": id, "category": cat}


@app.get("/download")
def download(file: str = "report.pdf"):
    return {"status": "ok", "downloading": file}


@app.get("/ping")
def ping_service(host: str = "8.8.8.8"):
    return {"status": "ok", "ping_target": host, "reply": "64 bytes from host: time=14ms"}

