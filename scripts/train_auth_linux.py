import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import OneClassSVM
import joblib
import os
import random

src_json = "data/processed/OpenSSH_2k.log_structured.json"
mdl_dest = "models/auth_linux/svm_v1.pkl"
vec_dest = "models/auth_linux/tfidf_v1.pkl"

def train_auth_linux():
    if not os.path.exists(src_json):
        print(f"[ERROR] {src_json} missing. Please ensure your parsed Loghub data is present.")
        return

    print("Loading OpenSSH Event Logs...")
    df = pd.read_json(src_json)
    txt_data = df['payload'].fillna("").astype(str).tolist()
    
    print(f"Original dataset size: {len(txt_data)}")

    # --- THE FIX: FILTERING THE BASELINE ---
    # We strip out obvious attack signatures so they don't pollute the "Normal" baseline
    malicious_sigs = ["Failed password", "Invalid user", "POSSIBLE BREAK-IN", "Connection closed by", "preauth", "error:"]
    
    clean_logs = [log for log in txt_data if not any(sig in log for sig in malicious_sigs)]
    print(f"Cleaned dataset size (Attack noise removed): {len(clean_logs)}")

    print("Injecting healthy SSH baseline (Successful publickey logins)...")
    synth_logs = []
    
    for _ in range(300):
        port = random.randint(30000, 60000)
        synth_logs.extend([
            f"Accepted publickey for root from 192.168.1.100 port {port} ssh2",
            f"pam_unix(sshd:session): session opened for user root by (uid=0)",
            f"Received disconnect from 192.168.1.100 port {port}: 11: disconnected by user"
        ])

    train_corp = clean_logs + synth_logs

    print("Vectorizing SSH text via Char N-Grams (TF-IDF)...")
    vec = TfidfVectorizer(analyzer='char', ngram_range=(3, 6), max_features=3000)
    x_vec = vec.fit_transform(train_corp)

    print(f"Training One-Class SVM on {x_vec.shape[0]} records...")
    svm_mdl = OneClassSVM(nu=0.01, kernel='rbf', gamma='scale')
    svm_mdl.fit(x_vec)

    os.makedirs(os.path.dirname(mdl_dest), exist_ok=True)
    joblib.dump(svm_mdl, mdl_dest)
    joblib.dump(vec, vec_dest)

    print(f"Artifact deployed: {mdl_dest}")
    print(f"Artifact deployed: {vec_dest}")

if __name__ == "__main__":
    train_auth_linux()
