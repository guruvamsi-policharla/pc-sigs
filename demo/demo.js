function getValue (name) { return document.getElementsByName(name)[0].value }
function setValue (name, val) { document.getElementsByName(name)[0].value = val }
function getText (name) { return document.getElementsByName(name)[0].innerText }
function setText (name, val) { document.getElementsByName(name)[0].innerText = val }

let prevSelectedCurve = 0
mcl.init(prevSelectedCurve).then(() => {
  setText('status', 'ok')
})

function onChangeSelectCurve () {
  const obj = document.selectCurve.curveType
  const idx = obj.selectedIndex
  const curveType = obj.options[idx].value | 0
  if (curveType === prevSelectedCurve) return
  prevSelectedCurve = curveType
  mcl.init(curveType).then(() => {
    setText('status', `curveType=${curveType} status ok`)
  })
}

function setRandG(generator){
  const temp = new mcl.Fr();
  temp.setByCSPRNG();
  return mcl.mul(generator,temp);
}

function comG(r, uv1, uv2, m){
  // assuming r is populated with randomness
  var com = [];
  com.push(
    mcl.add(
      mcl.mul(uv1[0], r[0]),
      mcl.mul(uv2[0], r[1])
    )
  );

  com.push(
    mcl.add(
      mcl.mul(uv1[1], r[0]),
      mcl.mul(uv2[1], r[1])
    )
  );

  mcl.add(com[1], m);
}

function comFr(r, uv1, uv2, m){
  // assuming r is populated with randomness
  var com = [];
  com.push(
    mcl.add(
      mcl.mul(uv1[0], r),
      mcl.mul(uv2[0], m)
    )
  );

  com.push(
    mcl.add(
      mcl.mul(uv1[1], r),
      mcl.mul(uv2[1], m)
    )
  );

  mcl.add(
    com[1],
    mcl.mul(uv1[0], m)
  );
}

function gencomkey(P1, P2){
  //Generate commitment keys wrt G1
  const alpha = new mcl.Fr();
  const t = new mcl.Fr();
  
  var u1 = [];
  u1.push(P1);
  alpha.setByCSPRNG();
  u1.push(mcl.mul(P1, alpha));

  var v1 = [];
  v1.push(P2);
  alpha.setByCSPRNG();
  v1.push(mcl.mul(P2, alpha));

  var u2 = [];
  t.setByCSPRNG();
  u2.push(mcl.mul(u1[0],t));
  t.setByCSPRNG();
  u2.push(mcl.mul(u1[1],t));

  var v2 = [];
  t.setByCSPRNG();
  v2.push(mcl.mul(v1[0],t));
  t.setByCSPRNG();
  v2.push(mcl.mul(v1[1],t));
  
  return [u1,u2,v1,v2]
}

function AHOkeygen(G, H){
  //Key generation procedure for the structure preserving signature -- AFG+10 CRYPTO
  const x = new mcl.Fr;
  x.setByCSPRNG();
  var X = mcl.mul(G,x);
  var Y = mcl.mul(H,x);
  var F = setRandG(G);
  var K = setRandG(G);
  var T = setRandG(G);
  return [x,X,Y,F,K,T];
}

function AHOsign(x, F, K, T, G, H, M){
  //Key generation procedure for the structure preserving signature -- AFG+10 CRYPTO
  //Signing procedure for the structure preserving signature -- AFG+10 CRYPTO
  const c = new mcl.Fr;
  const r = new mcl.Fr;
  const one = new mcl.Fr;
  one.setInt(1);

  c.setByCSPRNG();
  r.setByCSPRNG();

  const C = mcl.mul(F,c);
  const D = mcl.mul(H,c);
  const R = mcl.mul(G,r);
  const S = mcl.mul(H,r);

  var A = mcl.add(
    mcl.add(K, M),
    mcl.mul(T, r)
  );
  
  A = mcl.mul(
    A,
    mcl.div(one, mcl.add(x, c))
  );
  
  return [A,C,D,R,S];
}

function AHOverify(A, C, D, R, S, X, Y, F, T, K, G, H, M){
  var lhs = new mcl.GT;
  var rhs = new mcl.GT;
  var tempt = new mcl.GT;
  
  var temp1 = new mcl.G1;
  var temp2 = new mcl.G2;

  lhs = mcl.pairing(C, H);
  rhs = mcl.pairing(F, D);

  if(!lhs.isEqual(rhs))
    return false;
  
  lhs = mcl.pairing(R, H);
  rhs = mcl.pairing(G, S);

  if(!lhs.isEqual(rhs))
      return false;

  temp2 = mcl.add(Y, D);
  lhs = mcl.pairing(A, temp2);

  temp1 = mcl.add(K,M);
  rhs = mcl.pairing(temp1, H);
  tempt = mcl.pairing(T, S);
  rhs = mcl.mul(rhs, tempt);

  if(!lhs.isEqual(rhs))
      return false;

  return true;
}

function setup(){
  //Setup for the set pre-constrained group signature scheme
  const G = mcl.hashAndMapToG1('1');  
  const H = mcl.hashAndMapToG2('1');
  
  const M = mcl.hashAndMapToG1('hello world');

  const P1 = setRandG(G);
  const P2 = setRandG(H);
  
  const hG = mcl.hashAndMapToG1('input to random oracle here')

  const [u1,u2,v1,v2] = gencomkey(P1, P2);

  var u = [];
  var v = [];
  
  u.push(u2[0]);
  u.push(u2[1]);
  u[1] = mcl.add(u[1], P1); //u=(t1P1, t1Q1+P1) -- this is a different Q see Groth-Sahai

  v.push(v2[0]);
  v.push(v2[1]);
  v[1] = mcl.add(v[1], P2); //v=(t2P2, t2Q2+P2) -- this is a different Q see Groth-Sahai


  const minus1 = new mcl.Fr;
  minus1.setInt(-1);
  var _i2 = [];
  
  _i2.push(mcl.mul(v[0],minus1));
  _i2.push(mcl.mul(v[1],minus1));

  return [G,H,M,P1,P2,hG,u1,u2,v1,v2,u,v,_i2];
}

// Enc(m) = [r P, m + h(e(r mpk, H(id)))]
function IDenc (id, P, mpk, m) {
  const r = new mcl.Fr()
  r.setByCSPRNG()
  const Q = mcl.hashAndMapToG2(id)
  const e = mcl.pairing(mcl.mul(mpk, r), Q)
  return [mcl.mul(P, r), mcl.add(m, mcl.hashToFr(e.serialize()))]
}

// Dec([U, v]) = v - h(e(U, sk))
function IDdec (c, sk) {
  const [U, v] = c
  const e = mcl.pairing(U, sk)
  return mcl.sub(v, mcl.hashToFr(e.serialize()))
}

function onClickIBE () {
  const P = mcl.hashAndMapToG1('1')
  // keyGen
  const msk = new mcl.Fr()
  msk.setByCSPRNG()
  setText('msk', msk.serializeToHexStr())
  // mpk = msk P
  const mpk = mcl.mul(P, msk)
  setText('mpk', mpk.serializeToHexStr())

  // user KeyGen
  const id = getText('id')
  // sk = msk H(id)
  const sk = mcl.mul(mcl.hashAndMapToG2(id), msk)
  setText('sk', sk.serializeToHexStr())

  const m = new mcl.Fr()
  const msg = getValue('msg')
  console.log('msg', msg)
  m.setStr(msg)

  // encrypt
  const c = IDenc(id, P, mpk, m)
  setText('enc', c[0].serializeToHexStr() + ' ' + c[1].serializeToHexStr())
  // decrypt
  const d = IDdec(c, sk)
  setText('dec', d.getStr())

  // Generating com key
  const [G,H,M,P1,P2,hG,u,v,_i2] = setup();
  
  const [x,X,Y,F,K,T] = AHOkeygen(G, H);
  const [A,C,D,R,S] = AHOsign(x, F, K, T, G, H, M);
  const flag = AHOverify(A, C, D, R, S, X, Y, F, T, K, G, H, M);
  console.log(flag);
}

function bench (label, count, func) {
  const start = performance.now()
  for (let i = 0; i < count; i++) {
    func()
  }
  const end = performance.now()
  const t = (end - start) / count
  const roundTime = (Math.round(t * 1000)) / 1000
  setText(label, roundTime)
}