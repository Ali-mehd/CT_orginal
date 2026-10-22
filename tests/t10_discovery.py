import sys, os, json, io, tempfile, time, types, urllib.error, threading
os.environ["CFG_DATA"]=tempfile.mkdtemp(); sys.path.insert(0,'.')
import cfgscan, cfgweb as W
# ---------- 1) discover_github with a fake GitHub
SEARCH={"items":[
 {"full_name":"alice/v2ray-free","default_branch":"main","stargazers_count":50,"size":900},
 {"full_name":"bob/forked","default_branch":"main","stargazers_count":99,"size":9,"fork":True},
 {"full_name":"eve/archived","default_branch":"main","stargazers_count":80,"size":9,"archived":True},
 {"full_name":"evil/../../x","default_branch":"main","stargazers_count":70,"size":9},
 {"full_name":"zed/empty","default_branch":"main","stargazers_count":60,"size":0},
 {"full_name":"carol/xray lists","default_branch":"main","stargazers_count":40,"size":9}]}
TREE={"tree":[
 {"path":"sub/vless mix.txt","type":"blob","size":50000},   # space in path -> must be quoted
 {"path":"README.md","type":"blob","size":9000},
 {"path":"all.txt","type":"blob","size":100},                # too small
 {"path":"huge_v2ray.txt","type":"blob","size":9_000_000},   # too big
 {"path":"requirements.txt","type":"blob","size":4000},      # name not config-like
 {"path":"a/b/c/d/e/vless.txt","type":"blob","size":4000},   # too deep
 {"path":"vmess_sub.txt","type":"blob","size":80000},
 {"path":"dir","type":"tree"}]}
seen=[]
class Resp:
    def __init__(s,d): s.b=json.dumps(d).encode()
    def read(s,n=-1): return s.b
    def __enter__(s): return s
    def __exit__(s,*a): pass
class Op:
    def __init__(s,mode="ok"): s.mode=mode
    def open(s,rq,timeout=0):
        u=rq.full_url; seen.append(u)
        if s.mode=="rate": raise urllib.error.HTTPError(u,403,"rate",{},io.BytesIO(b""))
        if "/search/repositories" in u: return Resp(SEARCH)
        if "/git/trees/" in u: return Resp(TREE)
        raise AssertionError(u)
urls,info=cfgscan.discover_github(Op())
print("urls:",*urls,sep="\n  "); print("info:",info)
assert info["repos"]==1 and info["rate"] is False  # فقط alice معتبره؛ carol اسم نامعتبر داره
assert all(u.startswith("https://raw.githubusercontent.com/") for u in urls)
assert any("sub/vless%20mix.txt" in u for u in urls) and any(u.endswith("vmess_sub.txt") for u in urls)
assert not any(x in u for u in urls for x in ("forked","archived","empty","README","requirements","huge","a/b/c","..")) 
assert any("pushed%3A%3E" in u for u in seen)
u2,i2=cfgscan.discover_github(Op("rate")); print("rate-limited ->",u2,i2); assert i2["rate"] and u2==[]
print("discover_github OK")

def fixkeys():
    for k in list(W.LEARN["f"]):
        if k.startswith("u:") and len(k)!=18:
            W.LEARN["f"][W._uk(k[2:122] if len(k)>122 else k[2:])]=W.LEARN["f"].pop(k)
# ---------- 2) discover_sources end to end (mocked network)
W.STOP.clear(); W.S["stage"]="connected"; W.XRAY_PROC=None
good_urls=["https://raw.githubusercontent.com/a/b/main/one.txt","https://raw.githubusercontent.com/a/b/main/two.txt","https://raw.githubusercontent.com/a/b/main/tiny.txt","https://raw.githubusercontent.com/k/known/main/x.txt"]
cfgscan.discover_github=lambda op,stop=None,**k:(good_urls,{"rate":False,"err":"","repos":2})
def fake_fetch(urls,**k):
    n={"one.txt":120,"two.txt":45,"tiny.txt":5}.get(urls[0].rsplit("/",1)[-1],99)
    return ["vless://x"]*n,{urls[0]:{"got":n}}
cfgscan.fetch_sources=fake_fetch
db=W.load_db(); db["sources"].append({"url":good_urls[3],"on":True,"got":3,"alive":0}); W.save_db(db)
W.LEARN["disc_t"]=0; W.LEARN["disc_ok"]=True
W.discover_sources()
srcs=W.load_db()["sources"]; auto=[x for x in srcs if x.get("kind")=="auto"]
print("auto added:",[x["url"].rsplit('/',1)[-1] for x in auto],"| msg:",W.DISC["msg"])
assert [x["url"].rsplit('/',1)[-1] for x in auto]==["one.txt","two.txt"]     # tiny (<30) rejected, known skipped
assert W.LEARN["disc_t"]>0 and W.LEARN["disc_ok"]
t0=W.LEARN["disc_t"]; W.discover_sources(); assert W.LEARN["disc_t"]==t0      # not due -> no second run
W.save_settings({"autosrc":False}); W.LEARN["disc_t"]=0; W.discover_sources(); assert W.LEARN["disc_t"]==0   # switched off
W.save_settings({"autosrc":True})
print("discover_sources OK (adds >=30 configs only, skips known, honours schedule and the off switch)")
# cap: > AUTO_MAX removes the worst (by learned yield) and never re-suggests them
db=W.load_db(); db["sources"]=[x for x in db["sources"] if x.get("kind")!="auto"]
for i in range(W.AUTO_MAX+3): db["sources"].append({"url":f"https://raw.githubusercontent.com/z/z/main/s{i}.txt","on":True,"got":50,"alive":0,"kind":"auto","added":1})
W.save_db(db)
for i in range(3):   # make s0..s2 clearly bad: lots of tests, nothing useful
    W.LEARN["f"]["u:"+f"https://raw.githubusercontent.com/z/z/main/s{i}.txt"[:120]]=[300,3,3,0]
cfgscan.discover_github=lambda op,stop=None,**k:([],{"rate":False,"err":"","repos":0})
fixkeys(); W.LEARN["disc_t"]=0; W.discover_sources()
db=W.load_db(); autos=[x["url"].rsplit('/',1)[-1] for x in db["sources"] if x.get("kind")=="auto"]
print("after cap:",len(autos),"auto sources; removed:",sorted(r.rsplit('/',1)[-1] for r in db["removed"]))
assert len(autos)==W.AUTO_MAX and {"s0.txt","s1.txt","s2.txt"}<=set(r.rsplit('/',1)[-1] for r in db["removed"])
# ---------- 3) prune
db=W.load_db(); db["sources"]=[
 {"url":"https://raw.githubusercontent.com/p/p/main/dead.txt","on":True,"kind":"auto","got":60},
 {"url":"https://raw.githubusercontent.com/p/p/main/useful.txt","on":True,"kind":"auto","got":60},
 {"url":"https://raw.githubusercontent.com/p/p/main/young.txt","on":True,"kind":"auto","got":60},
 {"url":"https://raw.githubusercontent.com/p/p/main/manual.txt","on":True,"got":60}]; W.save_db(db)
W.LEARN["f"]={"u:"+"https://raw.githubusercontent.com/p/p/main/dead.txt":[400,4,4,0],
              "u:"+"https://raw.githubusercontent.com/p/p/main/useful.txt":[400,60,30,9],
              "u:"+"https://raw.githubusercontent.com/p/p/main/young.txt":[40,0,0,0],
              "u:"+"https://raw.githubusercontent.com/p/p/main/manual.txt":[900,1,1,0]}
fixkeys(); W.prune_sources(); st={x["url"].rsplit('/',1)[-1]:x["on"] for x in W.load_db()["sources"]}
mine={k:st[k] for k in ("dead.txt","useful.txt","young.txt","manual.txt")}; print("after prune:",mine); assert mine=={"dead.txt":False,"useful.txt":True,"young.txt":True,"manual.txt":True}
print("prune OK (own sources are never touched)")
# ---------- 4) API
srv=W.http.server.ThreadingHTTPServer(("127.0.0.1",0),W.H); W.PORT=srv.server_address[1]; W.TOKEN="TT"
threading.Thread(target=srv.serve_forever,daemon=True).start()
import http.client
def call(m,path,body=None):
    c=http.client.HTTPConnection("127.0.0.1",W.PORT); c.request(m,path,body=json.dumps(body) if body is not None else None,headers={"Host":f"127.0.0.1:{W.PORT}","X-T":"TT","Content-Type":"application/json"}); r=c.getresponse(); return r.status,json.loads(r.read() or b"{}")
W.S["stage"]="idle"; print("discover while not connected:",call("POST","/api/discover",{})[0],"|",W.DISC["msg"])
stt=call("GET","/api/state?t=TT")[1]; print("state keys ok:", "disc" in stt and "autosrc" in stt, "| autosrc rows:",len(stt["autosrc"]))
url="https://raw.githubusercontent.com/p/p/main/useful.txt"; call("POST","/api/delsource",{"url":url})
db=W.load_db(); assert url in db["removed"] and url not in [x["url"] for x in db["sources"]]; print("delete auto source -> not re-suggested OK")
print("ALL OK")
