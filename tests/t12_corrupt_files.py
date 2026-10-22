import sys,os,json,tempfile
os.environ["CFG_DATA"]=tempfile.mkdtemp(); sys.path.insert(0,'.')
import cfgweb as W
# corrupted / hostile learn.json and bad.json must neither crash nor create permanent quarantine
good_key="a"*16
open(W.LEARN_FILE,"w",encoding="utf-8").write(json.dumps({"f":{"p:vless":[1,2,3,4],"p:bad":[-5,1e99,"x",None],"u:rawurl":[1,1,1,1]},
  "s":{"p:vless":[10,2],"p:nan":[float("nan"),1],"p:neg":[-1,0],"p:over":[5,9],"t:x":[3,1],"p:str":["a","b"]},"runs":"junk","disc_t":-5,"disc_ok":"yes"}))
open(W.BAD_FILE,"w",encoding="utf-8").write(json.dumps({"salt":"s","h":{good_key:[2e9,1,"dead"],"b"*16:[float("inf"),1,"dead"],"c"*16:[1e12,1,"dead"],
  "d"*16:[100,-3,"dead"],"e"*16:[100,1,"evil"],"not-hex":[100,1,"dead"],"f"*16:"junk"}}))
W.LEARN["f"]={}; W.LEARN["s"]={}; W.BAD["h"].clear(); W.BAD["salt"]=""
W.learn_load(); W.bad_load()
print("learn f:",sorted(W.LEARN["f"])," s:",sorted(W.LEARN["s"])," runs:",W.LEARN["runs"]," disc_t:",W.LEARN["disc_t"])
print("bad h:",sorted(W.BAD["h"]),"| salt kept:",bool(W.BAD["salt"]))
assert sorted(W.LEARN["s"])==["p:vless"] and sorted(W.BAD["h"])==[good_key] and W.LEARN["runs"]==0 and W.LEARN["disc_t"]==0
assert "p:bad" not in W.LEARN["f"] and "u:rawurl" not in W.LEARN["f"]
# totally broken files
for f in (W.LEARN_FILE,W.BAD_FILE): open(f,"wb").write(b"\x00\xff garbage {{{")
W.learn_load(); W.bad_load(); print("garbage files -> no crash, salt:",bool(W.BAD["salt"]))
print("ALL OK")
