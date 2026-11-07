import os
import joblib
import pandas as pd
import streamlit as st
from scipy.sparse import hstack

from preprocess import decode_payload, extract_features_df, extract_handcrafted_features
from url_scanner import WebURLVulnerabilityScanner
from waf_engine import AIWafEngine

st.set_page_config(page_title="AI Web Vulnerability & WAF Dashboard", layout="wide")

st.title("🛡️ نظام اكتشاف ثغرات وهجمات الويب بالذكاء الاصطناعي (AI WAF & URL Scanner)")
st.markdown(
    "منصة متكاملة تجمع بين **فحص ثغرات المواقع بالرابط (Website URL Scanner)**، **تحليل طلبات HTTP بالذكاء الاصطناعي**، و**مراقبة جدار الحماية الحي (FastAPI WAF)**."
)

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_path = os.path.join(base_dir, "models", "waf_model.joblib")
log_file = os.path.join(base_dir, "logs", "waf_events.csv")

if not os.path.exists(model_path):
    st.warning("لم يتم العثور على نموذج مدرب. جاري تدريب النموذج الأولي الآن...")
    from train import train_and_evaluate
    train_and_evaluate()

artifact = joblib.load(model_path)
model = artifact["model"]
tfidf = artifact["tfidf"]
scaler = artifact.get("scaler")
model_name = artifact.get("model_name", "AI Classifier")
metrics_summary = artifact.get("metrics_summary", [])

st.sidebar.header("⚙️ معلومات محرك الذكاء الاصطناعي")
st.sidebar.success(f"النموذج المعتمد:\n**{model_name}**")
st.sidebar.markdown("""
**إمكانيات النظام:**
1. **فحص المواقع بالرابط:** ترويسات الأمان، HTTPS، الكوكيز، نماذج CSRF/XSS، وتقييم الدرجة من 100.
2. **فحص الطلبات (AI WAF):** اكتشاف `SQLi`, `XSS`, `Path/Cmd Attack`.
""")

if metrics_summary:
    st.sidebar.subheader("📈 أداء النماذج (Macro F1)")
    st.sidebar.dataframe(pd.DataFrame(metrics_summary)[["Model", "Macro F1"]], hide_index=True)

tab1, tab2, tab3, tab4 = st.tabs([
    "🌐 فحص موقع كامل بالرابط (Website URL Scanner)",
    "🔍 فحص طلب وتحليله بالذكاء الاصطناعي (XAI Payload Analyzer)",
    "📡 سجل جدار الحماية الحي (Live WAF SOC)",
    "📂 فحص ملفات السجلات (Batch Log Audit)",
])

with tab1:
    st.subheader("🌐 فحص ثغرات موقع ويب عبر الرابط (Passive & AI-Assisted URL Scanner)")
    target_url = st.text_input(
        "أدخل رابط الموقع أو الصفحة المراد فحصها:",
        value="https://example.com/search?q=python+course",
    )
    if st.button("بدء فحص الموقع والرابط الآن", type="primary"):
        scanner = WebURLVulnerabilityScanner()
        with st.spinner("جاري الاتصال بالرابط وفحص ترويسات الأمان والنماذج ومعاملات الرابط بالذكاء الاصطناعي..."):
            report = scanner.scan_url(target_url)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("درجة أمان الموقع", f"{report['security_score']} / 100", f"التقدير: {report.get('grade', '-')}")
        m2.metric("تصنيف الرابط (AI)", report["ai_url_analysis"]["prediction"])
        m3.metric("الثغرات والتحذيرات", len(report["vulnerabilities"]))
        m4.metric("زمن الفحص الكلي", f"{report['scan_duration_ms']} ms")

        if not report["reachable"]:
            st.warning(f"ملاحظة: تعذر الاتصال المباشر بالخادم البعيد ({report.get('error')})، وتم الاكتفاء بفحص بنية الرابط بالذكاء الاصطناعي.")

        if report["vulnerabilities"]:
            st.error(f"🚨 تم اكتشاف {len(report['vulnerabilities'])} ملاحظة/ثغرة أمنية:")
            st.dataframe(pd.DataFrame(report["vulnerabilities"]), use_container_width=True)
        else:
            st.success("✅ لم يتم العثور على ثغرات في إعدادات الصفحة أو الرابط!")

        if report["passed_checks"]:
            st.markdown("**✅ ضوابط الأمان المحققة:**")
            for chk in report["passed_checks"]:
                st.write(f"- {chk}")

with tab2:
    st.subheader("أدخل رابط الطلب أو الحمولة (HTTP URI / Payload)")
    example = st.selectbox(
        "أو اختر مثالاً جاهزاً للتجربة:",
        [
            "/search?q=select+best+laptop+and+update+windows&page=1",
            "/products?id=10' UNION SELECT username,password FROM users--",
            "/search?q=<script>alert(document.cookie)</script>",
            "/download?file=../../../../etc/passwd",
            "/ping?host=127.0.0.1;cat /etc/shadow",
        ],
    )
    user_input = st.text_area("الطلب المراد فحصه:", value=example, height=100)

    if st.button("تحليل الطلب وتسجيله في الجدار", type="primary"):
        engine = AIWafEngine()
        event = engine.inspect_request(user_input, client_ip="Dashboard-Test", method="GET")

        clean_text = event["normalized_payload"]
        X_tfidf = tfidf.transform([clean_text])
        X_hand_raw = extract_features_df([user_input]).values
        X_hand = scaler.transform(X_hand_raw) if scaler is not None else X_hand_raw
        X_combined = hstack([X_tfidf, X_hand])

        probs = model.predict_proba(X_combined)[0]
        classes = model.classes_

        col1, col2 = st.columns(2)
        with col1:
            if event["action"] == "ALLOWED":
                st.success(f"✅ **القرار: مسموح (200 OK) | التصنيف: ({event['prediction']}) | الثقة: {event['confidence']}%**")
            else:
                st.error(f"🚨 **القرار: حجب فوري (403 Forbidden) | نوع الهجوم: ({event['prediction']}) | الثقة: {event['confidence']}%**")

            st.markdown(f"**زمن استجابة نموذج الذكاء الاصطناعي:** `{event['latency_ms']} ms`")
            st.markdown("**الطلب بعد فك التشفير (Normalized Payload):**")
            st.code(clean_text)

        with col2:
            st.markdown("**نسب الثقة لكل فئة (Confidence Scores):**")
            prob_df = pd.DataFrame({"الفئة": classes, "الاحتمالية": probs}).sort_values(
                by="الاحتمالية", ascending=False
            )
            st.bar_chart(prob_df.set_index("الفئة"))

        st.subheader("📊 تفسير قرار الذكاء الاصطناعي (Extracted Security Features)")
        features = extract_handcrafted_features(user_input)
        st.json(features)

with tab3:
    st.subheader("📡 سجل أحداث جدار الحماية التطبيقي (Real-Time WAF Security Events)")
    if os.path.exists(log_file):
        logs_df = pd.read_csv(log_file)
        total_reqs = len(logs_df)
        blocked_reqs = int((logs_df["action"] == "BLOCKED").sum())
        allowed_reqs = int((logs_df["action"] == "ALLOWED").sum())
        avg_latency = round(logs_df["latency_ms"].mean(), 2) if total_reqs > 0 else 0.0

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("إجمالي الطلبات المفحوصة", total_reqs)
        k2.metric("الهجمات المحجوبة (403)", blocked_reqs)
        k3.metric("الطلبات المسموحة (200)", allowed_reqs)
        k4.metric("متوسط زمن الفحص", f"{avg_latency} ms")

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**توزيع التصنيفات الأمنية:**")
            st.bar_chart(logs_df["prediction"].value_counts())
        with c2:
            st.markdown("**قرارات الجدار (ALLOWED vs BLOCKED):**")
            st.bar_chart(logs_df["action"].value_counts())

        st.markdown("**جدول الأحداث الأمنية المفصل (الأحدث أولاً):**")
        st.dataframe(logs_df.iloc[::-1], use_container_width=True)
    else:
        st.info("لا توجد سجلات حتى الآن.")

with tab4:
    st.subheader("رفع ملف طلبات بصيغة CSV يحتوي على عمود `payload`")
    uploaded = st.file_uploader("اختر ملف CSV", type=["csv"])
    if uploaded is not None:
        df_batch = pd.read_csv(uploaded)
        if "payload" not in df_batch.columns:
            st.error("يجب أن يحتوي ملف CSV على عمود باسم `payload`.")
        else:
            clean_series = df_batch["payload"].astype(str).apply(decode_payload)
            X_t = tfidf.transform(clean_series)
            X_h_raw = extract_features_df(df_batch["payload"].astype(str).tolist()).values
            X_h = scaler.transform(X_h_raw) if scaler is not None else X_h_raw
            X_all = hstack([X_t, X_h])
            df_batch["Prediction"] = model.predict(X_all)
            st.dataframe(df_batch, use_container_width=True)
            st.bar_chart(df_batch["Prediction"].value_counts())
