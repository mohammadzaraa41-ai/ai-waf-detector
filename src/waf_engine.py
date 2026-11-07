import os
import time
from datetime import datetime
import joblib
import pandas as pd
from scipy.sparse import hstack

from preprocess import decode_payload, extract_features_df, extract_handcrafted_features


class AIWafEngine:
    """
    محرك جدار الحماية الذكي (AI WAF Engine):
    مسؤول عن تحميل النموذج المدرب، فحص الطلبات في الوقت الفعلي، وحفظ سجلات الأمان.
    """

    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.model_path = os.path.join(self.base_dir, "models", "waf_model.joblib")
        self.logs_dir = os.path.join(self.base_dir, "logs")
        self.log_file = os.path.join(self.logs_dir, "waf_events.csv")
        os.makedirs(self.logs_dir, exist_ok=True)

        if not os.path.exists(self.model_path):
            from train import train_and_evaluate
            train_and_evaluate(force_regenerate=False)

        artifact = joblib.load(self.model_path)
        self.model = artifact["model"]
        self.model_name = artifact.get("model_name", "Deep MLP")
        self.tfidf = artifact["tfidf"]
        self.scaler = artifact.get("scaler")

    def inspect_request(self, raw_payload: str, client_ip: str = "127.0.0.1", method: str = "GET") -> dict:
        start_time = time.perf_counter()

        clean_text = decode_payload(raw_payload)
        X_tfidf = self.tfidf.transform([clean_text])
        X_hand_raw = extract_features_df([raw_payload]).values
        X_hand = self.scaler.transform(X_hand_raw) if self.scaler is not None else X_hand_raw
        X_combined = hstack([X_tfidf, X_hand])

        prediction = str(self.model.predict(X_combined)[0])
        probs = self.model.predict_proba(X_combined)[0]
        confidence = round(float(max(probs)) * 100, 2)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        action = "ALLOWED" if prediction == "Normal" else "BLOCKED"
        features = extract_handcrafted_features(raw_payload)

        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "client_ip": client_ip,
            "method": method,
            "payload": raw_payload,
            "normalized_payload": clean_text,
            "prediction": prediction,
            "confidence": confidence,
            "action": action,
            "latency_ms": latency_ms,
            "entropy": features["entropy"],
            "special_chars": features["special_chars_count"],
        }

        self._log_event(event)
        return event

    def _log_event(self, event: dict):
        df_row = pd.DataFrame([event])
        write_header = not os.path.exists(self.log_file)
        df_row.to_csv(self.log_file, mode="a", header=write_header, index=False, encoding="utf-8")

