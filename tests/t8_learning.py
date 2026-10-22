import sys, os, json, random, tempfile, time
os.environ["CFG_DATA"]=tempfile.mkdtemp()
sys.path.insert(0,'.')
import cfgweb as W
W.learn_reset()
def mk(proto,net,sec,port,src="",alive=True,sites=None):
    return {"proto":proto,"network":net,"security":sec,"port":port,"srcurl":src,"raw":f"{proto}://SECRET-HOST-{random.random()}","host":"SECRET-HOST","alive":alive,"sites":sites or {}}
G=dict(yt=1,ig=1,tg=1)
# ---- 1) training + ordering
good=lambda: mk("vless","ws","tls",443,"https://good.src/a.txt")
bad =lambda: mk("vmess","tcp","none",80,"https://bad.src/b.txt")
for _ in range(60):
    g=good(); W.learn_record(g,"live"); W.learn_record(dict(g,sites=G),"site")
    b=bad(); b["alive"]=random.random()<0.1; W.learn_record(b,"live")
    if b["alive"]: W.learn_record(dict(b,sites=dict(yt=1)),"site")
sg,sb=W.learn_score(good()),W.learn_score(bad())
print("score good=%.2f bad=%.2f"%(sg,sb)); assert sg>3*sb
pool=[good() for _ in range(50)]+[bad() for _ in range(50)]
pool.sort(key=W.learn_order); top=pool[:50]
print("good ones in top half:",sum(1 for c in top if c["proto"]=="vless"),"/50"); assert sum(1 for c in top if c["proto"]=="vless")>=45
# exploration: an unknown kind is not buried forever (prior .25 vs bad ~.05)
unk=mk("trojan","grpc","tls",8443); assert W.learn_score(unk)>sb
print("unknown servers still explored: OK")
# ---- 2) decay
W.LEARN["f"]["x:test"]=[500.0,250.0,10.0,5.0]; W.learn_record(dict(good(),srcurl=""),"live")
k="p:vless"; assert W.LEARN["f"][k][0]<=400, W.LEARN["f"][k]
print("decay keeps counters bounded:",W.LEARN["f"][k][:2])
# ---- 3) persistence + privacy
W.learn_save(True); raw=open(W.LEARN_FILE,encoding="utf-8").read()
assert "SECRET-HOST" not in raw and "://SECRET" not in raw; print("learn.json contains no server addresses, size",len(raw),"bytes")
before=json.loads(json.dumps(W.LEARN["f"])); W.LEARN["f"]={}; W.learn_load()
assert set(W.LEARN["f"])==set(before); print("save/load round trip OK")
# ---- 4) summary
sm=W.learn_summary(); print("summary:",sm); assert sm["proto"]==["vless"] and sm["network"]==["ws"] and sm["port"]==["443"]
# ---- 5) reset
W.learn_reset(); assert W.learn_summary() is None and not W.LEARN_FILE.exists(); print("reset OK")
# ---- 6) honest benefit check on SYNTHETIC data (not real network!)
random.seed(7)
TRUE={"vless":0.12,"vmess":0.03,"trojan":0.06}; NET={"ws":1.6,"tcp":0.5,"grpc":1.0}
def world(n):
    out=[]
    for i in range(n):
        p=random.choice(list(TRUE)); nw=random.choice(list(NET)); port=random.choice([443,443,80,8443,2096])
        pr=min(0.9,TRUE[p]*NET[nw]*(1.5 if port==443 else .6))
        out.append((mk(p,nw,"tls",port,f"https://src{random.randint(1,8)}.x/l.txt"),random.random()<pr))
    return out
def run(order,budget,w):
    cs=sorted(w,key=lambda t: order(t[0])); return sum(1 for c,ok in cs[:budget] if ok)
trainw=world(1500)
for c,ok in trainw:
    c=dict(c,alive=ok); W.learn_record(c,"live"); 
    if ok: W.learn_record(dict(c,sites=G),"site")
testw=world(2000); budget=150
rnd=sum(run(lambda c: random.random(),budget,testw) for _ in range(20))/20
lrn=sum(run(W.learn_order,budget,testw) for _ in range(20))/20
print(f"synthetic: random order finds {rnd:.1f} good servers in {budget} tests; learned order finds {lrn:.1f}")
assert lrn>rnd*1.3
print("ALL OK")
