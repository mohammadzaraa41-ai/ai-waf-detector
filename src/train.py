import json
import os
import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from dataset_builder import generate_expanded_dataset
from preprocess import FEATURE_NAMES, decode_payload, extract_features_df


def export_cloud_weights(df_all: pd.DataFrame, api_dir: str) -> str:
    """
    تصدير أوزان نموذج الذكاء الاصطناعي الحقيقية (Real Trained ML Weights + TF-IDF + StandardScaler)
    إلى ملف JSON خفيف يعمل على Vercel Serverless وفي المتصفح بدون الحاجة لمكتبات خارجية ضخمة.
    """
    os.makedirs(api_dir, exist_ok=True)
    cloud_tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 4),
        max_features=320,
        norm="l2",
        sublinear_tf=False,
    )
    X_t = cloud_tfidf.fit_transform(df_all["clean_payload"])

    cloud_scaler = StandardScaler()
    X_h = cloud_scaler.fit_transform(extract_features_df(df_all["payload"].tolist()).values)

    X_cloud = hstack([X_t, X_h])
    y_cloud = df_all["label"]

    cloud_clf = LogisticRegression(C=3.0, max_iter=2000, random_state=42)
    cloud_clf.fit(X_cloud, y_cloud)

    vocab_sorted = sorted(cloud_tfidf.vocabulary_.items(), key=lambda x: x[1])
    vocab_map = {term: int(idx) for term, idx in vocab_sorted}

    payload_json = {
        "model_type": "Hybrid-CharNgram-LogReg-Export-v3.0",
        "classes": [str(c) for c in cloud_clf.classes_],
        "ngram_range": [2, 4],
        "feature_names": FEATURE_NAMES,
        "vocab": vocab_map,
        "idf": [round(float(v), 5) for v in cloud_tfidf.idf_],
        "scaler_mean": [round(float(v), 5) for v in cloud_scaler.mean_],
        "scaler_scale": [round(float(v), 5) for v in cloud_scaler.scale_],
        "coef": [[round(float(w), 5) for w in row] for row in cloud_clf.coef_],
        "intercept": [round(float(b), 5) for b in cloud_clf.intercept_],
    }

    out_path = os.path.join(api_dir, "model_weights.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload_json, f, ensure_ascii=False, separators=(",", ":"))
    return out_path


def train_and_evaluate(force_regenerate: bool = True):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, "data", "http_requests.csv")
    models_dir = os.path.join(base_dir, "models")
    api_dir = os.path.join(base_dir, "api")
    os.makedirs(models_dir, exist_ok=True)

    if force_regenerate or not os.path.exists(data_path):
        df = generate_expanded_dataset(data_path)
    else:
        df = pd.read_csv(data_path)

    print(f"[*] إجمالي العينات الفريدة في قاعدة البيانات: {len(df)}")
    print(df["label"].value_counts(), "\n")

    # 1. فك التشفير وتوحيد النص
    df["clean_payload"] = df["payload"].apply(decode_payload)

    # 2. تقسيم البيانات + إضافة مجموعة اختبار حدودية غير مرئية (Zero-Day Holdout) لقياس التعميم الحقيقي
    train_df, test_df = train_test_split(
        df, test_size=0.25, random_state=42, stratify=df["label"]
    )

    unseen_holdout = pd.DataFrame([
        # طلبات مطورين طبيعية تحتوي على كلمات SQL/JS/Linux في سياق نصي (تخدع النماذج البسيطة)
        ("/docs/sql-guide?example=select+id,name+from+customers+where+active=1", "Normal"),
        ("/forum/ask?title=why+does+union+select+throw+column+count+error+in+mysql", "Normal"),
        ("/support/chat?msg=my+file+path+../../images/avatar.png+returns+404+in+nginx", "Normal"),
        ("/blog/tutorial?topic=using+document.cookie+and+alert(1)+in+security+labs", "Normal"),
        ("/courses/linux?lesson=how+to+read+/etc/passwd+and+run+whoami+safely", "Normal"),
        # هجمات Zero-Day مموهة لم تظهر قوالبها في التدريب
        ("/api/v2/auth?user=admin'%0bOR%0b'7'='7'--", "SQLi"),
        ("/products/detail?id=99/**/AnD/**/Mod(29,9)=2--", "SQLi"),
        ("/search?q=<body/onpageshow=confirm`1`>", "XSS"),
        ("/profile/view?bio=<svg><animate+onbegin=alert(1)+attributeName=x>", "XSS"),
        ("/export/pdf?template=..%c0%af..%c0%afetc/passwd", "Path_Cmd_Attack"),
        ("/diag/trace?host=127.0.0.1%0aid%0auname", "Path_Cmd_Attack"),
    ], columns=["payload", "label"])
    unseen_holdout["clean_payload"] = unseen_holdout["payload"].apply(decode_payload)
    test_df = pd.concat([test_df, unseen_holdout], ignore_index=True)

    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=3000)
    X_train_tfidf = tfidf.fit_transform(train_df["clean_payload"])
    X_test_tfidf = tfidf.transform(test_df["clean_payload"])

    scaler = StandardScaler()
    X_train_hand = scaler.fit_transform(extract_features_df(train_df["payload"].tolist()).values)
    X_test_hand = scaler.transform(extract_features_df(test_df["payload"].tolist()).values)

    X_train = hstack([X_train_tfidf, X_train_hand])
    X_test = hstack([X_test_tfidf, X_test_hand])
    y_train = train_df["label"]
    y_test = test_df["label"]

    # 3. مقارنة عدة نماذج (للجانب التطبيقي في بحث التخرج)
    models = {
        "Logistic Regression (Baseline)": LogisticRegression(C=0.35, max_iter=2000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42),
        "Deep MLP (Neural Network)": MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=400, random_state=42),
    }

    best_model = None
    best_name = ""
    best_f1 = -1.0
    summary_rows = []
    confusion_matrices = {}

    labels_order = ["Normal", "SQLi", "XSS", "Path_Cmd_Attack"]

    for name, model in models.items():
        print("=" * 65)
        print(f"تدريب وتقييم نموذج: {name}")
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        report = classification_report(y_test, preds, digits=4)
        print(report)

        cm = confusion_matrix(y_test, preds, labels=labels_order)
        confusion_matrices[name] = cm.tolist()

        report_dict = classification_report(y_test, preds, output_dict=True)
        macro_p = report_dict["macro avg"]["precision"]
        macro_r = report_dict["macro avg"]["recall"]
        macro_f1 = report_dict["macro avg"]["f1-score"]

        summary_rows.append({
            "Model": name,
            "Accuracy": round(acc, 4),
            "Precision": round(macro_p, 4),
            "Recall": round(macro_r, 4),
            "Macro F1": round(macro_f1, 4),
        })

        if macro_f1 >= best_f1:
            best_f1 = macro_f1
            best_model = model
            best_name = name

    summary_df = pd.DataFrame(summary_rows)
    print("=" * 65)
    print("ملخص مقارنة النماذج (جدول جاهز لتقرير مشروع التخرج):")
    print(summary_df.to_string(index=False))

    # إعادة تدريب النموذج الأفضل على كامل البيانات شاملة الحالات الحدودية لتعزيز الدقة في الإنتاج
    full_df = pd.concat([df, unseen_holdout], ignore_index=True)
    X_full_t = tfidf.fit_transform(full_df["clean_payload"])
    X_full_h = scaler.fit_transform(extract_features_df(full_df["payload"].tolist()).values)
    best_model.fit(hstack([X_full_t, X_full_h]), full_df["label"])

    artifact = {
        "model": best_model,
        "model_name": best_name,
        "tfidf": tfidf,
        "scaler": scaler,
        "metrics_summary": summary_df.to_dict(orient="records"),
        "confusion_matrices": confusion_matrices,
        "labels_order": labels_order,
    }
    save_path = os.path.join(models_dir, "waf_model.joblib")
    joblib.dump(artifact, save_path)

    weights_path = export_cloud_weights(full_df, api_dir)
    weights_kb = round(os.path.getsize(weights_path) / 1024, 2)

    print("=" * 65)
    print(f"[+] أفضل نموذج معتمد: {best_name} (Macro F1: {best_f1:.4f})")
    print(f"[+] تم حفظ النموذج الكامل في: {save_path}")
    print(f"[+] تم تصدير أوزان السحابة الفعلية إلى: {weights_path} ({weights_kb} KB)\n")


if __name__ == "__main__":
    train_and_evaluate()
