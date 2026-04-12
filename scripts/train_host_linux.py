import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import OneClassSVM
import joblib
import os
import random

src_json = "data/processed/Linux_2k.log_structured.json"
mdl_dest = "models/host_linux_mac/svm_v1.pkl"
vec_dest = "models/host_linux_mac/tfidf_v1.pkl"

def train_linux_host():
    if not os.path.exists(src_json):
        print(f"Error: {src_json} missing.")
        return

    print("Loading Linux OS logs...")
    df = pd.read_json(src_json)
    txt_data = df['payload'].fillna("").astype(str).tolist()

    print("Injecting highly entropic benign baseline (Zero False Positive Mode)...")
    synth_logs = []
    
    # Massive randomization to teach the SVM that these logs are fluid background noise
    for _ in range(150):
        pid1 = random.randint(1000, 9999)
        pid2 = random.randint(1000, 9999)
        pid3 = random.randint(1000, 9999)
        uid = random.choice([1000, 1001, 0])
        session = random.randint(1, 500)
        port = random.randint(30000, 60000)
        
        synth_logs.extend([
            f"session opened for user meehir by (uid={uid})",
            f"pam_unix(sudo:session): session opened for user root by meehir(uid={uid})",
            f"systemd[1]: Started Process Core Dump (PID {pid1}/UID 0).",
            f"CRON[{pid2}]: (root) CMD ( /usr/lib/sysstat/sa1 1 1)",
            f"systemd[1]: Started Session {session} of user meehir.",
            f"sshd[{pid3}]: Accepted publickey for meehir from 192.168.1.50 port {port} ssh2"
        ])

    train_corp = txt_data + synth_logs

    print("Vectorizing system logs via TF-IDF...")
    vec = TfidfVectorizer(analyzer='word', ngram_range=(1, 3), max_features=3000)
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
    train_linux_host()
