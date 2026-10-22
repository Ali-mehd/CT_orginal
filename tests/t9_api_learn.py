import sys,os,threading,http.client,json,tempfile
os.environ["CFG_DATA"]=tempfile.mkdtemp(); sys.path.insert(0,'.')
import cfgweb as W
srv=W.http.server.ThreadingHTTPServer(("127.0.0.1",0),W.H); W.PORT=srv.server_address[1]; W.TOKEN="TT"
threading.Thread(target=srv.serve_forever,daemon=True).start()
def call(m,path,body=None):
    c=http.client.HTTPConnection("127.0.0.1",W.PORT); h={"Host":f"127.0.0.1:{W.PORT}","X-T":"TT","Content-Type":"application/json"}
    c.request(m,path,body=json.dumps(body) if body is not None else None,headers=h); r=c.getresponse(); return r.status,r.read()
W.LEARN["f"]={"p:vless":[40,30,20,15],"n:ws":[40,30,20,15],"o:443":[40,30,20,15]}
st=json.loads(call("GET","/api/state?t=TT")[1]); print("state.learn:",st["learn"])
assert st["learn"]["proto"]==["vless"]
print("reset:",call("POST","/api/learn_reset",{})[0]); st=json.loads(call("GET","/api/state?t=TT")[1]); print("state.learn after reset:",st["learn"]); assert st["learn"] is None
print("API OK")
