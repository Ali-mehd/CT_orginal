import sys, os, json, random, tempfile, time, hashlib
os.environ["CFG_DATA"]=tempfile.mkdtemp(); sys.path.insert(0,'.')
import cfgweb as W
W.learn_reset()
def mk(host,port=443,proto="vless",net="ws",src=""):
    return {"host":host,"port":port,"proto":proto,"network":net,"security":"tls","srcurl":src,"raw":f"{proto}://{host}:{port}","alive":True,"flags":set()}
now=[1_000_000.0]; real_time=time.time; time.time=lambda: now[0]
H=3600
# ---- 1) backoff schedule: dead 0h (first failure is not quarantine) -> 6h -> 24h -> 72h -> 168h (then stays)
c=mk("1.2.3.4"); random.seed(1)
exp=[0,6,24,72,168,168]
for i,h in enumerate(exp):
    W.bad_mark(c,"dead"); until=W.BAD["h"][W.bad_key(c)][0]; assert abs((until-now[0])/H-h)<1e-6,(i,until,h)
print("dead backoff 0/6/24/72/168/168 h OK")
# quarantined -> skipped (except ~5% exploration)
W.bad_mark(c,"dead") if False else None
sk=sum(W.bad_skip(c) for _ in range(2000)); print(f"quarantined server skipped {sk}/2000 (exploration ~5%)"); assert 1850<sk<1990
now[0]+=169*H; assert not W.bad_skip(c); print("quarantine expires OK")
# ---- 2) forgiveness: success after a dead strike clears it; danger is never forgiven
c2=mk("5.6.7.8"); W.bad_mark(c2,"dead"); W.bad_clear(c2,"dead"); assert W.bad_key(c2) not in W.BAD["h"]
c3=mk("9.9.9.9"); W.bad_mark(c3,"danger"); assert abs((W.BAD["h"][W.bad_key(c3)][0]-now[0])/H-24)<1e-6; W.bad_mark(c3,"danger"); W.bad_clear(c3,"dead","sites"); assert W.bad_key(c3) in W.BAD["h"]
assert all(W.bad_skip(c3) for _ in range(500)); print("danger: never forgiven, never re-explored (500/500 skipped)")
now[0]+=29*H*24; assert W.bad_skip(c3); now[0]+=2*H*24; assert not W.bad_skip(c3); print("danger quarantine lasts 30 days OK")
# ---- 3) sites: first failure is NOT quarantine, second is 3h
c4=mk("7.7.7.7"); W.bad_mark(c4,"sites"); assert not any(W.bad_skip(c4) for _ in range(200))
W.bad_mark(c4,"sites"); assert W.BAD["h"][W.bad_key(c4)][1]==2 and abs((W.BAD["h"][W.bad_key(c4)][0]-now[0])/H-3)<1e-6
print("sites: 1st failure tolerated, 2nd -> 3h OK")
# ---- 4) persistence + privacy: hashed with a per-install salt, survives a restart
W.bad_save(True); raw=open(W.BAD_FILE,encoding="utf-8").read()
assert "1.2.3.4" not in raw and "9.9.9.9" not in raw and "7.7.7.7" not in raw and "vless" not in raw; print("bad.json has no addresses, %d bytes"%len(raw))
snap=json.loads(json.dumps(W.BAD["h"])); salt=W.BAD["salt"]; W.BAD["h"].clear(); W.BAD["salt"]=""; W.bad_load()
assert W.BAD["salt"]==salt and set(W.BAD["h"])==set(snap); print("survives restart (salt + entries) OK")
# a different install (different salt) cannot map the hashes back to the same server
W2=W.BAD["salt"]; W.BAD["salt"]="other"; assert W.bad_key(c3)!=hashlib.sha256((W2+"|9.9.9.9|443|vless").encode()).hexdigest()[:16]; W.BAD["salt"]=W2
# ---- 5) security learning: risky feature gets a lower score and shows up in the summary
good=mk("a.example",proto="vless",net="ws",src="https://x/y.txt"); risky=mk("b.example",proto="vmess",net="tcp",src="https://x/y.txt")
for _ in range(40): W.sec_record(risky,True)
for _ in range(40): W.sec_record(good,False)
for _ in range(40): W.learn_record(dict(good),"live"); W.learn_record(dict(risky),"live")
s_good,s_risky=W.learn_score(good),W.learn_score(risky); print("score safe=%.3f risky=%.3f"%(s_good,s_risky)); assert s_risky<s_good*0.8
print("summary:",W.learn_summary()["risky"],"| quarantined:",W.learn_summary()["quarantined"]); assert any("vmess" in x for x in W.learn_summary()["risky"])
# ---- 6) learn.json also keeps security counters across restart, still without addresses
W.learn_save(True); W.LEARN["s"]={}; W.learn_load(); assert W.LEARN["s"]; assert "b.example" not in open(W.LEARN_FILE,encoding="utf-8").read(); print("security learning persists OK")
# ---- 7) exit flush: shutdown() must write both files even inside the 30s debounce window
W.learn_reset(); W.bad_load()
c5=mk("flush.example"); W.bad_mark(c5,"dead"); W.learn_record(dict(c5),"live")   # debounced -> not necessarily on disk yet
W.disconnect=lambda silent=False: None; W.WIN=None
for f in (W.LEARN_FILE,W.BAD_FILE):
    if f.exists(): f.unlink()
W._learn_state["dirty"]=True; W._bad_state["dirty"]=True; W._learn_state["saved"]=now[0]; W._bad_state["saved"]=now[0]   # inside debounce window
W.shutdown(); assert W.LEARN_FILE.exists() and W.BAD_FILE.exists(); print("shutdown() flushes learning + quarantine OK")
# ---- 8) reset wipes both
W.learn_reset(); assert not W.LEARN_FILE.exists() and not W.BAD_FILE.exists() and not W.BAD["h"] and not W.LEARN["s"]; print("reset wipes learning + quarantine + security OK")
time.time=real_time
print("ALL OK")
