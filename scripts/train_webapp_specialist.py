import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import OneClassSVM
import joblib
import os

json_src = "data/processed/Apache_2k.log_structured.json"
svm_dest = "models/network_app/svm_v1.pkl"
vec_dest = "models/network_app/tfidf_v1.pkl"

def train_webapp():
    if not os.path.exists(json_src):
        print(f"Error: {json_src} missing.")
        return

    print("Loading Apache Error logs...")
    df = pd.read_json(json_src)
    text_data = df['payload'].fillna("").astype(str).tolist()

    # --- THE BIAS FIX: Data Augmentation ---
    print("Injecting synthetic benign HTTP Access logs to remove protocol bias...")
    synthetic_access_logs = [
        "GET /index.html HTTP/1.1 200",
        "GET /images/logo.png HTTP/1.1 200",
        "POST /api/login HTTP/1.1 200",
        "GET /css/style.css HTTP/1.1 200",
        "GET /js/app.js HTTP/1.1 200",
        "GET /favicon.ico HTTP/1.1 200"
    ] * 100  # Multiply by 100 to give the SVM enough statistical weight

    # Combine the backend error logs with our new frontend access logs
    training_corpus = text_data + synthetic_access_logs

    print("Vectorizing syntax via Character N-Grams (TF-IDF)...")
    vec = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=3000)
    X_vec = vec.fit_transform(training_corpus)

    print(f"Training One-Class SVM on {X_vec.shape[0]} records...")
    svm_mdl = OneClassSVM(nu=0.01, kernel='rbf', gamma='scale')
    svm_mdl.fit(X_vec)

    os.makedirs(os.path.dirname(svm_dest), exist_ok=True)
    joblib.dump(svm_mdl, svm_dest)
    joblib.dump(vec, vec_dest)
    
    print(f"Artifact deployed: {svm_dest}")
    print(f"Artifact deployed: {vec_dest}")

if __name__ == "__main__":
    train_webapp()
