import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import OneClassSVM
import joblib
import os

src_json = "data/processed/LANL_WLS_2k.json"
mdl_dest = "models/auth_windows/svm_v1.pkl"
vec_dest = "models/auth_windows/tfidf_v1.pkl"

def train_auth_windows():
    if not os.path.exists(src_json):
        print(f"[ERROR] {src_json} missing. Please parse the LANL data first.")
        return

    print("Loading LANL Windows Auth Logs...")
    df = pd.read_json(src_json)
    train_corp = df['payload'].fillna("").astype(str).tolist()

    print("Vectorizing AD/Auth text via Char N-Grams (TF-IDF)...")
    # Using characters to catch anomalous Active Directory ticket structures
    vec = TfidfVectorizer(analyzer='char', ngram_range=(3, 6), max_features=3000)
    x_vec = vec.fit_transform(train_corp)

    print(f"Training One-Class SVM on {x_vec.shape[0]} records...")
    # Standard threshold for auth anomalies
    svm_mdl = OneClassSVM(nu=0.05, kernel='rbf', gamma='scale')
    svm_mdl.fit(x_vec)

    os.makedirs(os.path.dirname(mdl_dest), exist_ok=True)
    joblib.dump(svm_mdl, mdl_dest)
    joblib.dump(vec, vec_dest)

    print(f"Artifact deployed: {mdl_dest}")
    print(f"Artifact deployed: {vec_dest}")

if __name__ == "__main__":
    train_auth_windows()
