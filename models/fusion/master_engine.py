import re
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
            "AUTH_LINUX": {"mdl": "auth_linux/svm_v1.pkl", "vec": "auth_linux/tfidf_v1.pkl"},
            "AUTH_WINDOWS": {"mdl": "auth_windows/svm_v1.pkl", "vec": "auth_windows/tfidf_v1.pkl"},
            "HOST_LIN": {"mdl": "host_linux_mac/svm_v1.pkl", "vec": "host_linux_mac/tfidf_v1.pkl"},
            "HOST_WIN": {"mdl": "host_windows/svm_v1.pkl", "vec": "host_windows/tfidf_v1.pkl"}
        }
        self.cache_mdl = {}
        self.cache_vec = {}

    def fetch(self, tag):
        reg_tag = "HOST_LIN" if tag == "HOST_LINUX" else tag
        reg_tag = "HOST_WIN" if tag == "HOST_WINDOWS" else reg_tag
        
        if reg_tag not in self.registry:
            return None, None
        
        if reg_tag not in self.cache_mdl:
            mdl_path = os.path.join(self.base, self.registry[reg_tag]["mdl"])
            vec_path = os.path.join(self.base, self.registry[reg_tag]["vec"]) if self.registry[reg_tag]["vec"] else None
            
            if os.path.exists(mdl_path):
                self.cache_mdl[reg_tag] = joblib.load(mdl_path)
            else:
                self.cache_mdl[reg_tag] = None
                
            if vec_path and os.path.exists(vec_path):
                self.cache_vec[reg_tag] = joblib.load(vec_path)
            else:
                self.cache_vec[reg_tag] = None

        return self.cache_mdl[reg_tag], self.cache_vec.get(reg_tag)

class ChakshuFusion:
    def __init__(self):
        self.loader = AssetLoader()
        self.history = []
        self.win_size = 60
        
        self.weights = {
            "L3_L4": 1, "WEB_APP": 2, 
            "AUTH_LINUX": 3, "AUTH_WINDOWS": 3, 
            "HOST_LIN": 3, "HOST_WIN": 3
        }
        
        self.explainer = LimeTextExplainer(class_names=['Anomaly', 'Normal'], split_expression=r'\s+')
        self.whitelist = ["background_radiation", "healthcheck"]
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def get_proba_fn(self, mdl, vec):
        def predict_proba(texts):
            X_vec = vec.transform(texts)
            distances = mdl.decision_function(X_vec)
            prob_normal = 1 / (1 + np.exp(-distances))
            prob_anomaly = 1 - prob_normal
            return np.vstack([prob_anomaly, prob_normal]).T
        return predict_proba

    def check_os(self, payload):
        payload_lower = payload.lower()
        if any(x in payload_lower for x in ['c:\\', 'windows', 'cmd.exe']):
            return "HOST_WIN"
        if any(x in payload_lower for x in ['/bin/', 'linux', 'bash']):
            return "HOST_LIN"
        return None

    def extract_ip(self, payload, default_ip="0.0.0.0"):
        match = self.ip_pattern.search(payload)
        if match:
            return match.group(0)
        
        comp_match = re.search(r'(Comp[0-9]{6})', payload)
        if comp_match:
            return comp_match.group(1)
            
        return default_ip

    def process_frame(self, log):
        payload = str(log.get("payload", ""))
        tag = log.get("act", "L3_L4")
        ts_raw = log.get("ts", datetime.now().isoformat())
        
        if any(w in payload for w in self.whitelist):
            return None

        src_ip = self.extract_ip(payload, log.get("src_ip", "0.0.0.0"))
        
        try:
            ts = datetime.fromisoformat(ts_raw.replace('Z', ''))
        except:
            ts = datetime.now()

        if "HOST" in tag:
            detected = self.check_os(payload)
            if detected: tag = detected

        mdl, vec = self.loader.fetch(tag)
        if not mdl: return None

        forensics = []
        base_score = 0.0
        
        if tag == "L3_L4":
            feature_cols = ['dst_pt', 'b_in', 'b_out']
            feature_vals = [int(log.get("dst_pt", 0)), int(log.get("b_in", 0)), int(log.get("b_out", 0))]
            x_df = pd.DataFrame([feature_vals], columns=feature_cols)
            
            pred = mdl.predict(x_df)[0]
            base_score = 1.0 if pred == -1 else 0.0
            
            if base_score > 0.5:
                shap_path = os.path.join(self.loader.base, "network_flow", "shap_explainer_v1.pkl")
                if os.path.exists(shap_path):
                    try:
                        explainer = joblib.load(shap_path)
                        shap_vals = explainer.shap_values(x_df)
                        for idx, col in enumerate(feature_cols):
                            shap_score = shap_vals[0][idx]
                            if shap_score < -0.5:
                                forensics.append(f"{col}: {feature_vals[idx]} (SHAP: {shap_score:.2f})")
                        if not forensics:
                            forensics = ["High-Entropy Volumetric Flow Detected"]
                    except Exception as e:
                        forensics = [f"Structural Anomaly (SHAP Error: {str(e)})"]
                else:
                    forensics = ["Structural Anomaly (Explainer Not Found)"]
                    
        else:
            x_vec = vec.transform([payload])
            pred = mdl.predict(x_vec)[0]
            base_score = 1.0 if pred == -1 else 0.0
            
            if base_score > 0.5 and vec:
                try:
                    fn = self.get_proba_fn(mdl, vec)
                    exp = self.explainer.explain_instance(payload, fn, labels=(0,), num_features=5, num_samples=1000)
                    forensics = [str(text) for text, weight in exp.as_list(label=0) if weight > 0]
                except:
                    forensics = ["Structural Anomaly (XAI Timeout)"]

        bonus = 0.0
        cutoff = ts - timedelta(seconds=self.win_size)
        self.history = [h for h in self.history if h["ts"] > cutoff]
        
        if src_ip != "0.0.0.0":
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
