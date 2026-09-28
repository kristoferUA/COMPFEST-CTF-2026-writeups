from __future__ import annotations
import hashlib,hmac,json
from pathlib import Path

N=12
P=96
D=b'ASTERGATE/GMI/3'

def _f(x:int)->int:
    b=[(x>>i)&1 for i in range(4)]
    o=(b[0]^(b[1]&b[2]),b[1]^(b[2]&b[3]),b[2]^(b[3]&b[0]),b[3]^(b[0]&b[1]))
    return sum(v<<i for i,v in enumerate(o))

def _g(x:int)->int:
    l=x&15;r=x>>4
    return r|((l^_f(r))<<4)

def _h(x:int)->int:
    b=[(x>>i)&1 for i in range(4)]
    o=(b[0]^(b[2]&b[3]),b[1]^(b[0]&b[3]),b[2]^(b[0]&b[1]),b[3]^(b[1]&b[2]))
    return sum(v<<i for i,v in enumerate(o))

def _q(x:int)->int:
    l=x&15;r=x>>4
    return r|((l^_h(r))<<4)

def _rank(rows:list[int])->int:
    a=rows[:];r=0
    for c in range(8):
        p=next((i for i in range(r,len(a)) if (a[i]>>c)&1),None)
        if p is None:continue
        a[r],a[p]=a[p],a[r]
        for i in range(len(a)):
            if i!=r and ((a[i]>>c)&1):a[i]^=a[r]
        r+=1
    return r

def matrix(index:int)->list[int]:
    if not 0<=index<4096:raise ValueError('matrix index')
    c=0
    while True:
        z=hashlib.sha256(D+b'/matrix/'+index.to_bytes(2,'little')+c.to_bytes(2,'little')).digest()
        rows=list(z[:8])
        if _rank(rows)==8:return rows
        c+=1

def _apply(rows:list[int],x:int)->int:
    return sum(((rows[i]&x).bit_count()&1)<<i for i in range(8))

def _permute(state:bytes)->bytes:
    x=int.from_bytes(state,'little');y=0
    for i in range(P):y|=((x>>i)&1)<<((29*i+17)%P)
    return y.to_bytes(N,'little')

def _material(key:list[int])->bytes:
    if len(key)!=N or any(not 0<=x<(1<<20) for x in key):raise ValueError('key')
    return b''.join(x.to_bytes(3,'little') for x in key)

def _round_material(key:list[int])->bytes:
    return b''.join((x>>8).to_bytes(2,'little') for x in key)

def _round_key(key:list[int],r:int)->bytes:
    return hashlib.sha256(D+b'/round/'+bytes([r])+_round_material(key)).digest()[:N]

def encrypt_block(block:bytes,key:list[int])->bytes:
    if len(block)!=N:raise ValueError('block')
    s=bytes(block)
    for r in range(3):
        k=_round_key(key,r)
        s=bytes(_g(a^b) for a,b in zip(s,k))
        s=_permute(s)
    k=_round_key(key,3)
    s=bytes(a^b for a,b in zip(s,k))
    out=[]
    for i,x in enumerate(s):
        seed=key[i]; rows=matrix(seed>>8)
        out.append(_apply(rows,_q(x))^(seed&255))
    return bytes(out)

def _root(key:list[int])->bytes:
    return hashlib.sha256(D+b'/seal/'+_material(key)).digest()

def open_sealed(obj:dict,key:list[int])->bytes:
    root=_root(key);nonce=bytes.fromhex(obj['n']);ct=bytes.fromhex(obj['c']);tag=bytes.fromhex(obj['t'])
    ek=hashlib.sha256(D+b'/enc/'+root).digest();mk=hashlib.sha256(D+b'/mac/'+root).digest()
    if not hmac.compare_digest(tag,hmac.new(mk,D+nonce+ct,hashlib.sha256).digest()[:16]):raise ValueError('authentication')
    stream=bytearray();i=0
    while len(stream)<len(ct):
        stream.extend(hmac.new(ek,nonce+i.to_bytes(8,'little'),hashlib.sha256).digest());i+=1
    return bytes(a^b for a,b in zip(ct,stream))

if __name__=='__main__':
    m=json.loads(Path('records.json').read_text())
    print(f"blocks={sum(x['count'] for x in m['sets'])}")
