"""usage: rtp_corpus.py <seeds.jsonl> <per-kind-count> <max-seed-bytes> <out.jsonl> [kind,kind,...]"""
import sys,json,random,collections
seedf,per,maxb,outf=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),sys.argv[4]
only=set(sys.argv[5].split(',')) if len(sys.argv)>5 else None
rows=[json.loads(l) for l in open(seedf)]
groups=collections.defaultdict(list)
for r in rows:
    if len(r['in'])//2<=maxb and (only is None or r['k'] in only): groups[(r['k'],r['op'])].append(r)
rnd=random.Random(2024)
MTUS=[6,8,12,50,100,500,1200,1400,1500,65535]
def mutate(b):
    b=bytearray(b)
    for _ in range(rnd.randint(1,3)):
        if not b: b=bytearray(rnd.randbytes(rnd.randint(1,8))); continue
        k=rnd.randrange(11); i=rnd.randrange(len(b))
        if k==0: b[i]^=1<<rnd.randrange(8)
        elif k==1: b[i]=rnd.choice([0,1,0xff,0x7f,0x80,rnd.randrange(256)])
        elif k==2: del b[rnd.randrange(len(b)):]
        elif k==3: b+=rnd.randbytes(rnd.randint(1,8))
        elif k==4: del b[i:i+rnd.randint(1,4)]
        elif k==5: b[i:i]=b[i:i+rnd.randint(1,4)]
        elif k==6: b[i:i]=rnd.randbytes(rnd.randint(1,4))
        elif k==7 and len(b)>4: j=rnd.randrange(len(b)); b[i],b[j]=b[j],b[i]
        elif k==8: b[0]=rnd.randrange(256)
        elif k==9 and len(b)>1: b[1]=rnd.randrange(256)
        elif k==10: b=bytearray(bytes(b)+bytes(b))
    return bytes(b)
out={}
for (kind,op),seeds in sorted(groups.items()):
    local={}
    for s in seeds: local[(s['k'],s['op'],s['mtu'],s['in'])]=1
    tries=0
    while len(local)<per and tries<per*40:
        s=rnd.choice(seeds); data=mutate(bytes.fromhex(s['in']))
        mtu=s['mtu']
        if op=='payload' and rnd.random()<0.5: mtu=rnd.choice(MTUS+[s['mtu']])
        local[(kind,op,mtu,data.hex())]=1; tries+=1
    out.update(local)
with open(outf,'w') as f:
    for (k,op,mtu,h) in out: f.write(json.dumps({'k':k,'op':op,'mtu':mtu,'in':h})+'\n')
print(len(out),'vectors',len(groups),'groups')
