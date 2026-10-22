import re,sys,glob,os
d=sys.argv[1]
rx=re.compile(r"^func \((\w+) \*?(\w+)\) (Unmarshal|Payload)\((.*?)\)([^{]*)\{\s*(//.*)?$")
log='''package %s

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

var oracleMu sync.Mutex

func oracleSeed(kind, op string, mtu int, b []byte) {
	path := os.Getenv("ORACLE_OUT")
	if path == "" {
		return
	}
	oracleMu.Lock()
	defer oracleMu.Unlock()
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		j, _ := json.Marshal(map[string]any{"k": kind, "op": op, "mtu": mtu, "in": hex.EncodeToString(b)})
		f.Write(append(j, '\\n'))
		f.Close()
	}
}
'''
n=0
for pkgdir,pkg in ((d,'rtp'),(d+'/codecs','codecs')):
    for f in glob.glob(pkgdir+'/*.go'):
        if f.endswith('_test.go') or f.endswith('oracle_log.go'): continue
        lines=open(f).read().split('\n'); out=[]; ch=False
        for l in lines:
            m=rx.match(l)
            if m and (pkg=='codecs' or m.group(2)=='Packet'):
                recv,typ,op,args,rest,_c=m.groups()
                if op=='Unmarshal':
                    am=re.match(r'^(\w+) \[\]byte$',args)
                    if am:
                        out.append(l); out.append('\toracleSeed("%s", "unmarshal", 0, %s)'%(typ,am.group(1))); ch=True; n+=1; continue
                else:
                    am=re.match(r'^(\w+) uint16, (\w+) \[\]byte$',args)
                    if am:
                        mt,pl=am.groups()
                        if mt=='_':
                            l=l.replace('_ uint16','oracleMtu uint16'); mt='oracleMtu'
                        out.append(l); out.append('\toracleSeed("%s", "payload", int(%s), %s)'%(typ,mt,pl)); ch=True; n+=1; continue
            out.append(l)
        if ch: open(f,'w').write('\n'.join(out))
    open(pkgdir+'/oracle_log.go','w').write(log%pkg)
print('hooked',n)
