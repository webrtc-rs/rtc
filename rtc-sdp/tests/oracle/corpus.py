import json,base64,random,sys
# usage: corpus.py <dir with sdp_oracle.jsonl> <count> <max seed bytes>; writes <dir>/sdp_corpus.jsonl
S=sys.argv[1]
seeds=[]
seen=set()
for l in open(S+'/sdp_oracle.jsonl'):
    r=json.loads(l)
    if r['in'] in seen: continue
    seen.add(r['in'])
    s=base64.b64decode(r['in']).decode('latin1')
    if len(s)<=int(sys.argv[3]): seeds.append(s)
CODEC_SEEDS = [
    "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\na=rtcp-fb:111 transport-cc\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 97\r\na=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\n",
    "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=video 9 RTP/AVPF 96\r\na=rtcp-fb:* nack\r\na=rtcp-fb:* ccm fir\r\na=rtcp-fb:96 nack\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\nm=audio 9 RTP/AVP 0 8 9\r\na=rtpmap:8 PCMA/8000\r\na=rtcp-fb:8 nack\r\n",
    "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=video 9 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\na=fmtp:96 a=b c\r\nm=video 9 RTP/AVP 96\r\na=rtpmap:96 VP9/90000\r\na=fmtp:96 x\r\na=rtcp-fb:96 goog-remb\r\n",
]
seeds.extend(CODEC_SEEDS)
rnd=random.Random(1234)
garb=['96','*','255','256','-1','+5','opus/48000/2','VP8/90000/','/90000','rtpmap:96','fmtp:96 ','rtcp-fb:*', ' ', 'x', '-1', '99999999999999999999', '0', '\x00', 'IN', 'IP4', 'IP9', 'a b c', '1/2/3', '//', '=', 'é']
def mutate(s):
    ops=rnd.randint(1,3)
    for _ in range(ops):
        lines=s.split('\n')
        k=rnd.randrange(8+4)
        if not lines: break
        i=rnd.randrange(len(lines))
        if k==0: del lines[i]
        elif k==1: lines.insert(i,lines[i])
        elif k==2 and i+1<len(lines): lines[i],lines[i+1]=lines[i+1],lines[i]
        elif k==3:
            s='\n'.join(lines).replace('\r\n','\n'); continue
        elif k==4:
            s='\n'.join(lines); s=s[:rnd.randrange(len(s)+1)]; continue
        elif k==5 or k==6:
            toks=lines[i].replace('\r','').split(' ')
            j=rnd.randrange(len(toks)); toks[j]=rnd.choice(garb)
            lines[i]=' '.join(toks)+('\r' if lines[i].endswith('\r') else '')
        elif k==7: lines.insert(i,rnd.choice(['x=foo\r','a=\r','a=foo:\r','m=\r','=\r','a\r','c=IN IP4 0.0.0.0\r','b=AS:100\r','k=clear:abc\r','z=1 2\r','r=1 2 3\r','t=0 0\r','i=hello\r','u=http://x\r','e=a@b\r','p=123\r']))
        elif k==8: lines[i]=lines[i].replace('=','= ',1)
        elif k==9: lines[i]=lines[i].rstrip('\r')
        elif k==10 and len(lines[i])>2: lines[i]=lines[i][:rnd.randrange(len(lines[i]))]+('\r' if lines[i].endswith('\r') else '')
        elif k==11: lines.insert(i,'')
        s='\n'.join(lines)
    return s
out={}
for s in seeds: out[s]=1
n=int(sys.argv[2])
while len(out)<n:
    out[mutate(rnd.choice(seeds))]=1
with open(S+'/sdp_corpus.jsonl','w') as f:
    for s in out: f.write(json.dumps({'in':base64.b64encode(s.encode('latin1')).decode()})+'\n')
print(len(out),'inputs')
