import sys,os,threading,http.client,json,tempfile,shutil,base64,time
from pathlib import Path
os.environ["CFG_DATA"]=tempfile.mkdtemp(); os.environ["CFG_NO_RESTART"]="1"; sys.path.insert(0,'.')
import cfgweb as W
# رابط برنامه برای تکامل. ریشه‌ی تکامل رو روی یک کپی موقت می‌بریم تا به فایل‌های واقعی دست نخوره.
REAL=Path(".").resolve().parent; T=Path(tempfile.mkdtemp()); (T/"app").mkdir(); (T/"tests").mkdir()
for f in (REAL/"app").iterdir():
    if f.is_file() and f.suffix in (".py",".html",".txt"): shutil.copy2(f,T/"app"/f.name)
shutil.copy2(REAL/"tests"/"t12_corrupt_files.py",T/"tests"/"t12_corrupt_files.py")
D=T/"data"; D.mkdir(); W._ev.init(T,D)
srv=W.http.server.ThreadingHTTPServer(("127.0.0.1",0),W.H); W.PORT=srv.server_address[1]; W.TOKEN="TT"
threading.Thread(target=srv.serve_forever,daemon=True).start()
def call(m,path,body=None,tok=True):
    c=http.client.HTTPConnection("127.0.0.1",W.PORT); h={"Host":f"127.0.0.1:{W.PORT}","Content-Type":"application/json"}
    if tok: h["X-T"]="TT"
    c.request(m,path,body=json.dumps(body) if body is not None else None,headers=h); r=c.getresponse(); return r.status,r.read(),r.getheader("Content-Disposition")
# بدون توکن همه رد می‌شن
for m,pa in (("GET","/api/evolve"),("GET","/api/evolve/report"),("POST","/api/evolve/apply")): assert call(m,pa,{} if m=="POST" else None,tok=False)[0]==403
st=json.loads(call("GET","/api/evolve")[1]); assert st["cap_mb"]==20 and st["autotune"] and st["usage"]["code_max_kb"]>0, st
code,body,disp=call("GET","/api/evolve/report"); assert code==200 and "ctreport" in disp
rep=W._ev.open_report(body.decode("utf-8")); assert rep["kind"]=="ctreport" and "stats" in rep["ctx"] and rep["ctx"]["speed_now"]
assert b"http" not in json.dumps(rep["ctx"]["sources"]).encode(), rep["ctx"]["sources"]
print("report via API ok; sources in report:",len(rep["ctx"]["sources"]))
# تنظیم‌ها
assert json.loads(call("POST","/api/evolve/cap",{"mb":50})[1])["ok"] and json.loads(call("GET","/api/evolve")[1])["cap_mb"]==50
assert json.loads(call("POST","/api/evolve/cap",{"mb":"x"})[1])["ok"] is False
call("POST","/api/evolve/autotune",{"on":False}); assert json.loads(call("GET","/api/evolve")[1])["autotune"] is False
# وصله‌ی خراب و خوب از راه API
r=json.loads(call("POST","/api/evolve/inspect",{"b64":base64.b64encode(b"junk").decode()})[1]); assert r["ok"] is False
r=json.loads(call("POST","/api/evolve/inspect",{"b64":"@@@"})[1]); assert r["ok"] is False
rid=W._ev.make_report({})[0]
good=(T/"app"/"report.py").read_text(encoding="utf-8")+"\n# api-patch\n"
data=W._ev.build_patch(T,{"app/report.py":good.encode()},rid,"آزمایش API","یادداشت")
r=json.loads(call("POST","/api/evolve/inspect",{"b64":base64.b64encode(data).decode()})[1]); assert r["ok"], r
r0=json.loads(call("POST","/api/evolve/apply",{"b64":base64.b64encode(data).decode()})[1]); assert r0["ok"] is False and "خاموش" in " ".join(r0["errors"]), r0  # پیش‌فرض: نصب وصله خاموشه
assert json.loads(call("POST","/api/settings",{"evolve_ok":True})[1])["ok"] and W.load_settings().get("evolve_ok") is True
assert json.loads(call("POST","/api/evolve/apply",{"b64":base64.b64encode(data).decode()})[1])["ok"]
for _ in range(120):
    j=json.loads(call("GET","/api/evolve")[1])["job"]
    if j["state"]!="running": break
    time.sleep(1)
assert j["state"]=="done" and j["need_restart"], j
assert "api-patch" in (T/"app"/"report.py").read_text(encoding="utf-8")
# هنگام جستجو نصب نمی‌شه
W.S["stage"]="running"; r=json.loads(call("POST","/api/evolve/apply",{"b64":base64.b64encode(data).decode()})[1]); W.S["stage"]="idle"; assert r["ok"] is False
r=json.loads(call("POST","/api/evolve/rollback",{"mode":"last"})[1]); assert r["ok"] and "api-patch" not in (T/"app"/"report.py").read_text(encoding="utf-8")
# گزارش کامل با وضعیت پر: هیچ آدرس، شناسه، دامنه، اسم، کلید، IP یا مسیر شخصی نباید توش بیاد
import cfgscan
raw="vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443?security=tls&type=ws&sni=secret.example.com&path=%2Fx&pbk=PUBLICKEYPUBLICKEYPUBLICKEYPUBLICKEY#myname"
c=cfgscan.parse(raw); c.update(ms=120,alive=True,reachable=True,src="auto")
W.POOL["active"]=[c]; W.POOL["standby"]=[c,c]; W.LEARN["f"]={"p:vless":[40,30,20,15],"n:ws":[40,30,20,15],"u:"+"a"*16:[5,3,2,1]}
W.S["log"]=["وصل شد 203.0.113.5:8443","C:\\Users\\Ali\\AppData x"]; W.NETP["net"]={"udp":"yes","ip":"203.0.113.77"}
W._ev.note_error("t",RuntimeError("fail at 203.0.113.9 user@mail.com "+raw))
for plain in (False,True):
    code,body,disp=call("GET","/api/evolve/report"+("?plain=1" if plain else "")); assert code==200 and (".txt" in disp)==plain
    txt=body.decode("utf-8"); rj=json.dumps(W._ev.open_report(txt),ensure_ascii=False)
    for bad in ("198.51.100.7","11111111-2222","secret.example.com","myname","PUBLICKEYPUB","203.0.113","C:\\Users","user@mail.com","vless://"): assert bad not in txt and bad not in rj,(plain,bad)
    r=W._ev.open_report(txt); assert r["system"]["os"] and r["system"]["errors"] and r["ctx"]["pool"]["active"][0]["proto"]=="vless" and r["ctx"]["learn_tables"]["proto"]
print("full report: system+errors+pool present, nothing personal leaked")
print("API OK")
