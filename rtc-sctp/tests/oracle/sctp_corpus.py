"""usage: sctp_corpus.py <packets.hex> <chunks.hex> <count> <max-bytes> <out.jsonl>
Seeds: whole packets, plus lone chunks wrapped in a packet. Mutates and re-checksums."""
import sys,json,random
pk,ck,count,maxb,outf=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),sys.argv[5]
T=[]
for i in range(256):
    c=i
    for _ in range(8): c=(c>>1)^0x82F63B78 if c&1 else c>>1
    T.append(c)
def crc32c(b):
    c=0xFFFFFFFF
    for x in b: c=T[(c^x)&0xFF]^(c>>8)
    return c^0xFFFFFFFF
def fix(b):
    b=bytearray(b)
    if len(b)<12: return bytes(b)
    b[8:12]=b'\0\0\0\0'
    b[8:12]=crc32c(bytes(b)).to_bytes(4,'little')
    return bytes(b)
def wrap(chunk):
    pad=(-len(chunk))%4
    hdr=(5000).to_bytes(2,'big')+(5000).to_bytes(2,'big')+(1).to_bytes(4,'big')+b'\0\0\0\0'
    return fix(hdr+chunk+bytes(pad))
seeds=set()
for l in open(pk):
    l=l.strip()
    if l and len(l)//2<=maxb: seeds.add(bytes.fromhex(l))
for l in open(ck):
    l=l.strip()
    if l and len(l)//2+16<=maxb: seeds.add(wrap(bytes.fromhex(l)))
seeds=sorted(seeds)
rnd=random.Random(77)
def mutate(b):
    b=bytearray(b)
    for _ in range(rnd.randint(1,3)):
        if len(b)<14: b+=rnd.randbytes(4)
        k=rnd.randrange(12); i=rnd.randrange(12,len(b))
        if k==0: b[i]^=1<<rnd.randrange(8)
        elif k==1: b[i]=rnd.choice([0,1,0xff,0x7f,0x80,rnd.randrange(256)])
        elif k==2: del b[rnd.randrange(12,len(b)):]
        elif k==3: b+=rnd.randbytes(rnd.randint(1,8))
        elif k==4: del b[i:i+rnd.randint(1,4)]
        elif k==5: b[i:i]=b[i:i+rnd.randint(1,8)]
        elif k==6: b[i:i]=rnd.randbytes(rnd.randint(1,4))
        elif k==7: b+=rnd.choice(seeds)[12:]
        elif k==8: b[12]=rnd.randrange(256)
        elif k==9 and len(b)>15: b[14:16]=rnd.choice([b'\x00\x00',b'\xff\xff',b'\x00\x04',bytes([0,rnd.randrange(4,64)])])
        elif k==10 and len(b)>13: b[13]=rnd.randrange(256)
        elif k==11: b[rnd.randrange(0,8)]=rnd.randrange(256)
    return bytes(b)
out={}
for s in seeds: out[s]=1
tries=0
while len(out)<count and tries<count*40:
    m=mutate(rnd.choice(seeds))
    if rnd.random()<0.8: m=fix(m)
    out[m]=1; tries+=1
with open(outf,'w') as f:
    for s in out: f.write(json.dumps({'in':s.hex()})+'\n')
print(len(out),'inputs from',len(seeds),'seeds')
