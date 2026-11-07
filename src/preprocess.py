import math
import re
import urllib.parse
from collections import Counter
import numpy as np
import pandas as pd


FEATURE_NAMES = [
    "length",
    "special_chars_count",
    "special_chars_ratio",
    "digits_ratio",
    "entropy",
    "sql_indicators",
    "xss_indicators",
    "path_traversal_indicators",
    "cmd_indicators",
]


def decode_payload(payload: str) -> str:
    """
    فك ترميز طلب الويب (URL Decoding & Multi-layer Encoding) وتوحيد النص
    حتى لا يتمكن المهاجم من تجاوز النموذج عبر الترميز المزدوج أو الثلاثي.
    """
    if not isinstance(payload, str):
        return ""
    decoded = payload
    for _ in range(3):
        decoded = urllib.parse.unquote_plus(decoded)
    return decoded.lower().strip()


def calculate_shannon_entropy(text: str) -> float:
    """
    حساب عشوائية النص (Shannon Entropy) - الطلبات المشفرة أو المعقدة
    تمتلك قيمة عشوائية أعلى من الطلبات الطبيعية.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_handcrafted_features(payload: str) -> dict:
    """
    استخراج الخصائص الإحصائية والهيكلية من طلب HTTP (Handcrafted Features)
    لتفسير قرارات النموذج (Explainable AI).
    """
    decoded = decode_payload(payload)

    # الأنماط الدلالية السياقية (لتقليل الإنذارات الكاذبة False Positives عند وجود كلمات إنجليزية عادية)
    sql_keywords = len(re.findall(
        r"(union\s+all\s+select|union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|information_schema|sleep\s*\(|pg_sleep\s*\(|benchmark\s*\(|extractvalue\s*\(|waitfor\s+delay|'\s*or\s+|\"\s*or\s+|'\s*and\s+|'\s*&&\s*|--\s*$|/\*.*\*/|having\s+\d+=\d+|0x[0-9a-f]{4,})",
        decoded
    ))
    xss_patterns = len(re.findall(
        r"(<script|javascript:|onerror\s*=|onload\s*=|ontoggle\s*=|onfocus\s*=|onstart\s*=|onmouseover\s*=|alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\(|atob\s*\(|document\.cookie|document\.domain|<img\s|<svg|<iframe|<math|<marquee|fromcharcode)",
        decoded
    ))
    path_patterns = len(re.findall(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/etc/hosts|/etc/issue|c:\\windows|win\.ini|boot\.ini|/proc/self|php://filter)",
        decoded
    ))
    cmd_patterns = len(re.findall(
        r"(;\s*(cat|ls|id|whoami|uname|ping|nc|curl|bash|sh)\b|\|\s*(cat|ls|id|whoami|uname|sh|bash)\b|\|\|\s*(curl|wget|ping|sh|nc)\b|&&\s*(cat|ls|id|whoami|calc)\b|&\s*nc\s+|\$\([^\)]+\)|`[^`]+`)",
        decoded
    ))

    special_chars = sum(1 for c in decoded if c in "'\"<>%;()&|=+-*/\\`$")
    digits_count = sum(1 for c in decoded if c.isdigit())
    length = len(decoded)

    return {
        "length": length,
        "special_chars_count": special_chars,
        "special_chars_ratio": round(special_chars / max(length, 1), 4),
        "digits_ratio": round(digits_count / max(length, 1), 4),
        "entropy": round(calculate_shannon_entropy(decoded), 4),
        "sql_indicators": sql_keywords,
        "xss_indicators": xss_patterns,
        "path_traversal_indicators": path_patterns,
        "cmd_indicators": cmd_patterns,
    }


def extract_features_df(payloads: list[str]) -> pd.DataFrame:
    """تحويل قائمة من الطلبات إلى جدول خصائص رقمية."""
    rows = [extract_handcrafted_features(p) for p in payloads]
    return pd.DataFrame(rows)[FEATURE_NAMES]
