"""Deterministic byte-level mutation corpus from hex seeds.
usage: bincorpus.py <seeds.hex> <count> <max-seed-bytes> <out.jsonl> [rtcp-length-fix]"""
import sys,json,random
seedf,count,maxb,outf=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),sys.argv[4]
fixlen=len(sys.argv)>5
seeds=sorted({bytes.fromhex(l.strip()) for l in open(seedf) if l.strip()})
seeds=[s for s in seeds if 0<len(s)<=maxb]
import os
only=os.environ.get('ONLY_PT')  # e.g. "205:15" or "206"
if only:
    pt,_,fmt=only.partition(':')
    seeds=[s for s in seeds if len(s)>1 and s[1]==int(pt) and (not fmt or s[0]&31==int(fmt))]
rnd=random.Random(99)
def mutate(b):
    b=bytearray(b)
    for _ in range(rnd.randint(1,3)):
        if not b: b=bytearray(rnd.randbytes(rnd.randint(1,8))); continue
        k=rnd.randrange(12); i=rnd.randrange(len(b))
        if k==0: b[i]^=1<<rnd.randrange(8)
        elif k==1: b[i]=rnd.choice([0,1,0xff,0x7f,0x80,rnd.randrange(256)])
        elif k==2: del b[rnd.randrange(len(b)):]
        elif k==3: b+=rnd.randbytes(rnd.randint(1,8))
        elif k==4: del b[i:i+rnd.randint(1,4)]
        elif k==5: b[i:i]=b[i:i+rnd.randint(1,4)]
        elif k==6 and len(b)>4: j=rnd.randrange(len(b)); b[i],b[j]=b[j],b[i]
        elif k==7: b[i:i]=rnd.randbytes(rnd.randint(1,4))
        elif k==8: b=bytearray(b+rnd.choice(seeds))
        elif k==9 and len(b)>=4:
            b[2:4]=rnd.choice([b'\x00\x00',b'\xff\xff',bytes([0,rnd.randrange(1,40)])])
        elif k==10: b[0]=(b[0]&0xe0)|rnd.randrange(32)
        elif k==11 and len(b)>1: b[1]=rnd.randrange(256)
    if fixlen and len(b)>=4 and rnd.random()<0.5:
        pad=(-len(b))%4; b+=bytes(pad); b[2:4]=((len(b)//4)-1).to_bytes(2,'big')
    return bytes(b)
out={s:1 for s in seeds}
tries=0
while len(out)<count and tries<count*50:
    out[mutate(rnd.choice(seeds))]=1; tries+=1
with open(outf,'w') as f:
    for s in out: f.write(json.dumps({'in':s.hex()})+'\n')
print(len(out),'inputs from',len(seeds),'seeds')
