import os
import joblib
import pandas as pd
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from dataset_builder import generate_expanded_dataset
from preprocess import decode_payload, extract_features_df


def train_and_evaluate(force_regenerate: bool = True):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, "data", "http_requests.csv")
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)

    if force_regenerate or not os.path.exists(data_path):
        df = generate_expanded_dataset(data_path)
    else:
        df = pd.read_csv(data_path)

    print(f"[*] إجمالي العينات الفريدة في قاعدة البيانات: {len(df)}")
    print(df["label"].value_counts(), "\n")

    # 1. فك التشفير وتوحيد النص
    df["clean_payload"] = df["payload"].apply(decode_payload)

    # 2. تقسيم البيانات أولاً قبل ملائمة (Fit) المحولات لمنع تسرب البيانات (Data Leakage)
    train_df, test_df = train_test_split(
        df, test_size=0.25, random_state=42, stratify=df["label"]
    )

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
        "Logistic Regression (Baseline)": LogisticRegression(max_iter=2000),
        "Random Forest": RandomForestClassifier(n_estimators=200, random_state=42),
        "Deep MLP (Neural Network)": MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=400, random_state=42),
    }

    best_model = None
    best_name = ""
    best_f1 = -1.0
    summary_rows = []

    for name, model in models.items():
        print("=" * 65)
        print(f"تدريب وتقييم نموذج: {name}")
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        report = classification_report(y_test, preds, digits=4)
        print(report)

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

    # حفظ أفضل نموذج مع أداة الـ TF-IDF والـ Scaler
    artifact = {
        "model": best_model,
        "model_name": best_name,
        "tfidf": tfidf,
        "scaler": scaler,
        "metrics_summary": summary_df.to_dict(orient="records"),
    }
    save_path = os.path.join(models_dir, "waf_model.joblib")
    joblib.dump(artifact, save_path)
    print("=" * 65)
    print(f"[+] أفضل نموذج معتمد: {best_name} (Macro F1: {best_f1:.4f})")
    print(f"[+] تم حفظ النموذج بنجاح في: {save_path}\n")

    # 4. اختبار حي على طلبات جديدة تماماً (بما فيها حالات خادعة لاختبار دقة النموذج)
    test_cases = [
        "/search?q=select+best+laptop+and+update+windows",  # طلب طبيعي يحتوي على كلمات select و update
        "/api/v1/user?id=42' UNION SELECT username,password FROM users--",  # SQLi
        "/comments/post?msg=%3Csvg%2Fonload%3Dalert%28document.cookie%29%3E",  # Encoded XSS
        "/download?doc=..%2F..%2F..%2Fetc%2Fpasswd",  # Encoded Path Traversal
        "/ping?host=192.168.1.1;cat /etc/shadow",  # Command Injection
        "/blog/article?title=how-to-prevent-sql-injection-in-python",  # طلب طبيعي
    ]

    print("اختبار النموذج على حالات عملية جديدة (Live Inference Test):")
    print("-" * 65)
    for req in test_cases:
        clean_req = decode_payload(req)
        x_t = tfidf.transform([clean_req])
        x_h = scaler.transform(extract_features_df([req]).values)
        x_all = hstack([x_t, x_h])
        pred = best_model.predict(x_all)[0]
        conf = max(best_model.predict_proba(x_all)[0]) * 100
        print(f"الطلب: {req}")
        print(f"  -> التصنيف: [{pred}] (نسبة الثقة: {conf:.1f}%)\n")


if __name__ == "__main__":
    train_and_evaluate()
