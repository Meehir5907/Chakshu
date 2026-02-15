import json
import random
from datetime import datetime, timedelta

def get_ip():
    return f"192.168.1.{random.randint(2, 254)}"

def mk_ds(n, a_flag=False):
    d = []
    t = datetime.now()
    for i in range(n):
        t += timedelta(seconds=random.randint(1, 5))
        sip = get_ip()
        dip = "10.0.0.5"
        spt = random.randint(1024, 65535)
        dpt = random.choice([80, 443, 22, 53])
        prt = "TCP" if dpt in [80, 443, 22] else "UDP"
        eid = 1001
        act = "ALLOW"
        bi = random.randint(100, 5000)
        bo = random.randint(500, 10000)

        if a_flag and (n // 2) <= i < (n // 2) + 50:
            sip = "10.0.0.199"
            dpt = random.randint(1, 1024)
            act = "DROP"
            bi = 64
            bo = 0
            eid = 1002

        r = {
            "ts": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": sip,
            "dst_ip": dip,
            "src_pt": spt,
            "dst_pt": dpt,
            "proto": prt,
            "evt_id": eid,
            "act": act,
            "b_in": bi,
            "b_out": bo
        }
        d.append(r)
    return d

out = mk_ds(1000, True)
with open("chakshu_train.json", "w") as f:
    json.dump(out, f, indent=2)
