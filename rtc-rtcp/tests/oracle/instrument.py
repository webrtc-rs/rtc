"""Insert a seed-logging call at the top of Go methods `Unmarshal`-like functions.
usage: instrument.py <moddir> <package> <regex of 'func (recv Type) Name(arg []byte' lines to hook>
Adds oracle_log.go with oracleSeed([]byte) writing hex lines to $ORACLE_OUT."""
import re,sys,os,glob
d,pkg,rx=sys.argv[1],sys.argv[2],sys.argv[3]
pat=re.compile(rx)
n=0
for f in glob.glob(d+'/*.go'):
    if f.endswith('_test.go') or f.endswith('oracle_log.go'): continue
    src=open(f).read().split('\n'); out=[]; changed=False
    for i,l in enumerate(src):
        out.append(l)
        m=pat.match(l)
        if m and l.rstrip().endswith('{'):
            arg=re.search(r'\((\w+) \[\]byte',l)
            if arg:
                out.append('\toracleSeed(%s)'%arg.group(1)); changed=True; n+=1
    if changed: open(f,'w').write('\n'.join(out))
open(d+'/oracle_log.go','w').write('''package %s

import (
	"encoding/hex"
	"os"
	"sync"
)

var oracleMu sync.Mutex

func oracleSeed(b []byte) {
	path := os.Getenv("ORACLE_OUT")
	if path == "" {
		return
	}
	oracleMu.Lock()
	defer oracleMu.Unlock()
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		f.WriteString(hex.EncodeToString(b) + "\\n")
		f.Close()
	}
}
'''%pkg)
print('hooked',n)
