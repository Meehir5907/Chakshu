import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import OneClassSVM
import joblib
import os
import random

src_json = "data/processed/Windows_2k.log_structured.json"
mdl_dest = "models/host_windows/svm_v1.pkl"
vec_dest = "models/host_windows/tfidf_v1.pkl"

def train_windows_host():
    if not os.path.exists(src_json):
        print(f"Error: {src_json} missing. Did you run init_parsers.py?")
        return

    print("Loading Windows Event Logs...")
    df = pd.read_json(src_json)
    txt_data = df['payload'].fillna("").astype(str).tolist()

    print("Injecting highly entropic Windows baseline (Active Directory noise)...")
    synth_logs = []
    
    # Injecting healthy Active Directory background noise with proper Hex entropy
    for _ in range(150):
        # Using real hex to match Windows EVTX formats (e.g., 0x4a8)
        pid = hex(random.randint(100, 8000))
        session = hex(random.randint(100000, 999999))
        
        synth_logs.extend([
            f"An account was successfully logged on. Subject User SID: S-1-5-18. Logon ID: {session}",
            f"A new process has been created. Creator Process ID: {pid}. Process Name: C:\\Windows\\System32\\svchost.exe",
            # THE FIX: Give the AI a normal PowerShell baseline so LIME can isolate the malicious flags
            f"A new process has been created. Creator Process ID: {pid}. Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine: powershell.exe -NoProfile -Command Exit",
            f"The Windows Filtering Platform has permitted a connection. Process ID: {pid}"
        ])

    train_corp = txt_data + synth_logs

    print("Vectorizing EVTX text via Character N-Grams (TF-IDF)...")
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
    train_windows_host()
