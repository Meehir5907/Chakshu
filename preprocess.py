import pandas as pd
from sklearn.preprocessing import LabelEncoder

with open("chakshu_train.json", "r") as f:
    df = pd.read_json(f)

df['ts'] = pd.to_datetime(df['ts'])

le_ip = LabelEncoder()
df['src_ip_enc'] = le_ip.fit_transform(df['src_ip'])
df['dst_ip_enc'] = le_ip.fit_transform(df['dst_ip'])

le_prt = LabelEncoder()
df['proto_enc'] = le_prt.fit_transform(df['proto'])

le_act = LabelEncoder()
df['act_enc'] = le_act.fit_transform(df['act'])

fts = ['src_ip_enc', 'dst_ip_enc', 'src_pt', 'dst_pt', 'proto_enc', 'evt_id', 'act_enc', 'b_in', 'b_out']
X = df[fts]
