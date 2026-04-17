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

        if reg_tag not in self.cache_mdl:
            cfg = self.registry.get(reg_tag)
            if not cfg: return None, None
            
            path_mdl = os.path.join(self.base, cfg["mdl"])
            path_vec = os.path.join(self.base, cfg["vec"]) if cfg["vec"] else None
            
            if not os.path.exists(path_mdl):
                return None, None
            
            self.cache_mdl[reg_tag] = joblib.load(path_mdl)
            self.cache_vec[reg_tag] = joblib.load(path_vec) if path_vec else None
            
        return self.cache_mdl[reg_tag], self.cache_vec[reg_tag]

class ChakshuFusion:
    def __init__(self):
        self.loader = AssetLoader()
        self.explainer = LimeTextExplainer(class_names=['Anomaly', 'Normal'], split_expression=r'\s+')
        self.history = []
        self.all_alerts = []
        self.weights = {
            "L3_L4": 1, "WEB_APP": 2, 
            "AUTH_LINUX": 3, "AUTH_WINDOWS": 3, 
            "HOST_LIN": 3, "HOST_WIN": 3
        }
        
        self.whitelist = [
            "user news", "user cyrus", "cupsd shutdown", "session closed", "ALERT exited",
            "jk2_init", "mod_jk",
            "Unrecognized packageExtended", "SQM:", "TrustedInstaller", "Session:", "cached package applicability"
        ]

    def extract_ip(self, payload, default_ip):
        if default_ip != "0.0.0.0" and default_ip != "":
            return default_ip
            
        match_std = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', payload)
        if match_std: return match_std.group(0)
        
        match_hyphen = re.search(r'rhost=([0-9]{1,3}(?:-[0-9]{1,3}){3})', payload)
        if match_hyphen: return match_hyphen.group(1).replace('-', '.')
        
        return default_ip

    def check_os(self, payload):
        win_sig = ["C:\\", ".exe", ".dll", "EventID", "Microsoft"]
        lin_sig = ["/var/log", "systemd", "pam_unix", "sshd", "root", "/tmp", "authentication failure"]
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

        base_score = 0.0
        forensics = []

        if tag == "L3_L4":
            feature_columns = ['dst_pt', 'b_in', 'b_out']
            feature_values = [int(log.get("dst_pt", 0)), int(log.get("b_in", 0)), int(log.get("b_out", 0))]
            network_dataframe = pd.DataFrame([feature_values], columns=feature_columns)
            
            prediction = mdl.predict(network_dataframe)[0]
            base_score = 1.0 if prediction == -1 else 0.0
            
            if base_score > 0.5:
                shap_filepath = "models/network_flow/shap_explainer_v1.pkl"
                if os.path.exists(shap_filepath):
                    try:
                        shap_explainer = joblib.load(shap_filepath)
                        shap_values = shap_explainer.shap_values(network_dataframe)
                        
                        for feature_index, column_name in enumerate(feature_columns):
                            feature_shap_score = shap_values[0][feature_index]
                            if feature_shap_score < -0.5: 
                                forensics.append(f"{column_name}: {feature_values[feature_index]} (SHAP: {feature_shap_score:.2f})")
                        
                        if not forensics:
                            forensics = ["High-Entropy Volumetric Flow Detected"]
                            
                    except Exception as exception_message:
                        forensics = [f"Structural Anomaly (SHAP Error: {str(exception_message)})"]
                else:
                    forensics = ["Structural Anomaly (Explainer Not Found)"]
                    
        else:
            payload_vector = vec.transform([payload])
            prediction = mdl.predict(payload_vector)[0]
            base_score = 1.0 if prediction == -1 else 0.0
            
            if base_score > 0.5 and vec:
                try:
                    probability_function = self.get_proba_fn(mdl, vec)
                    lime_explanation = self.explainer.explain_instance(payload, probability_function, labels=(0,), num_features=5, num_samples=1000)
                    forensics = [str(text_feature) for text_feature, feature_weight in lime_explanation.as_list(label=0) if feature_weight > 0]
                except:
                    forensics = ["Structural Anomaly (XAI Timeout)"]

        bonus = 0.0
        
        if src_ip != "0.0.0.0":
            for prev_alert in self.history:
                if prev_alert["src_ip"] == src_ip and prev_alert["tag"] != tag:
                    bonus = 0.3
                    break

        specialist_weight = self.weights.get(tag, 1)
        final_score = min(1.0, (base_score * specialist_weight / 3.0) + bonus)
        
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
            self.all_alerts.append(alert)
        
        return alert
