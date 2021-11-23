#include <mcl/bn256.hpp>
using namespace mcl::bn256;
using namespace std;

GT e(const G1& G1, const G2& G2){
    //Helper function for carrying out pairings in-line
    GT ttemp;
    pairing(ttemp,G1,G2);
    return ttemp;
}

void gencomkey(G1* u1, G1* u2, const G1& P1){
    //Generate commitment keys wrt G1
    Fr alpha1, t1;
    u1[0] = P1;
    alpha1.setRand();
    u1[1] = P1*alpha1;

    t1.setRand();
    u2[0] = u1[0]*t1;
    u2[1] = u1[1]*t1;
}

void gencomkey(G2* v1, G2* v2, const G2& P2){
    //Generate commitment keys wrt G2
    Fr alpha2, t2;
    v1[0] = P2;
    alpha2.setRand();
    v1[1] = P2*alpha2;

    t2.setRand();
    v2[0] = v1[0]*t2;
    v2[1] = v2[0]*t2;
}

void comG1(G1* com, Fr* r, G1* u1, G1* u2, const G1& m){
    //Commit to a group element in G1
    r[0].setRand();
    r[1].setRand();

    com[0] = u1[0]*r[0] + u2[0]*r[1];
    com[1] = u1[1]*r[0] + u2[1]*r[1] + m;
}

void comG2(G2* com, Fr* s, G2* v1, G2* v2, const G2& m){
    //Commit to a group element in G2
    s[0].setRand();
    s[1].setRand();

    com[0] = v1[0]*s[0] + v2[0]*s[1];
    com[1] = v1[1]*s[0] + v2[1]*s[1] + m;
}

void comFr(G1* com, Fr& r, G1* u1, G1* u2, const Fr& m){
    //Commit to a field element and output a commitment in G1
    r.setRand();

    com[0] = u1[0]*r + u2[0]*m;
    com[1] = u1[1]*r + u2[1]*m + u1[0]*m;
}

void comFr(G2* com, Fr& r, G2* v1, G2* v2, const Fr& m){
    //Commit to a field element and output a commitment in G2
    r.setRand();
    
    com[0] = v1[0]*r + v2[0]*m;
    com[1] = v1[1]*r + v2[1]*m + v1[0]*m;
}

void Hash(G1& P, const std::string& m){
    //Hash a string to an element in the group using methods from mcl library
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}

void setRandG1(G1& op, const G1& G){
    //Assign a random group element to the first parameter
    Fr tempF;
    tempF.setRand();
    op = G*tempF;
}

void setRandG2(G2& op, const G2& H){
    //Assign a random group element to the first parameter
    Fr tempF;
    tempF.setRand();
    op = H*tempF;
}

void AHOkeygen(G1& F, G1& K, G1& T, G1& X, G2& Y, Fr& x, const G1& G, const G2& H){
    //Key generation procedure for the structure preserving signature -- AFG+10 CRYPTO
    x.setRand();
    X = G*x;
    Y = H*x;
    setRandG1(F, G);
    setRandG1(K, G);
    setRandG1(T, G);
}

void AHOsign(G1& A, G1& C, G2& D, G1& R, G2& S, const G1& F, const G1& T, const G1& K, const G1& M, const G1& G, const G2& H, const Fr& x){
    //Signing procedure for the structure preserving signature -- AFG+10 CRYPTO
    Fr c,r;
    c.setRand();
    r.setRand();
    C = F*c;
    D = H*c;
    R = G*r;
    S = H*r;

    G1::add(A, K, M);
    A = K + M + T*r;
    A = A*(1/(x+c));
}

struct proof{
    //Groth-Sahai proof attached as part of the set pre-constrained group signature. Number of variables may seem cumbersome but this helps with understanding logic in the code.
    G2 combeta1[2], comgamma1[2], combeta2[2], comgamma2[2], comsk[2], comD[2], comS[2], pi3[2][2], pi4[2][2], pi5[2][2], pi6[2][2];
    G1 comA[2], comC[2], comR[2], compk[2], theta1, theta2, theta3[2], theta4[2][2], theta5[2][2], theta6[2][2], theta7, theta8;
};

struct secrets{
    //Secrets which will be committed to as part of the set pre-constrained group signature.
    Fr sk, beta1, gamma1, beta2, gamma2, sbeta1, sgamma1, sbeta2, sgamma2, ssk, rpk[2], rA[2], rC[2], rR[2], sD[2], sS[2];
    G1 A, C, R, pk;
    G2 D, S;
};

struct publicparam{
    //Public paramters in the entire construction
    G1 G, Pw1, Pw2, L, ct1, ct2, M, Q1, Q2, F, K, T, X, id1, u1[2], u2[2], u[2], P1, Tinv, Kinv;
    G2 H, Y, v1[2], v2[2], v[2], P2, _i2[2], id2, Hinv;
    Fp12 idT;
    string m;
};

void SPCsign(proof &p, secrets &s, publicparam &pp){
    //Constructs a Groth-Sahai proof satisfying necessary constraints for set pre-constrained group signature scheme.
    //Some helper variables
    pp.Hinv = -pp.H;
    pp.Tinv = -pp.T;
    pp.Kinv = -pp.K;
    
    //Constraint Creation
    Fr Tt[2], TT[2][2];
    s.beta1.setRand(); //ApplePSI enc
    s.gamma1.setRand(); //ApplePSI enc
    s.beta2.setRand(); //ApplePSI enc
    s.gamma2.setRand(); //ApplePSI enc
    
    
    setRandG1(pp.Pw1, pp.G); //Just a random group element
    setRandG1(pp.Pw2, pp.G); //Just a random group element

    pp.ct1 = pp.Pw1*s.beta1 + s.pk + pp.L*s.gamma1; //ct1 = G^sk . Pw1^beta1 . L^gamma1 (Constraint 1)
    pp.ct2 = pp.Pw2*s.beta2 + s.pk + pp.L*s.gamma2; //ct2 = G^sk . Pw2^beta2 . L^gamma2 (Constraint 7)

    pp.Q1 = pp.M*s.beta1 + pp.G*s.gamma1; //Q1 = Hy^beta1 . G^gamma1 (Constraint 2)
    pp.Q2 = pp.M*s.beta2 + pp.G*s.gamma2; //Q2 = Hy^beta2 . G^gamma2 (Constraint 8)
    
    //Proof construction
    comG1(p.compk, s.rpk, pp.u1, pp.u2, s.pk);
    comFr(p.comsk, s.ssk, pp.v1, pp.v2, s.sk);
    comFr(p.combeta1, s.sbeta1, pp.v1, pp.v2, s.beta1);
    comFr(p.comgamma1, s.sgamma1, pp.v1, pp.v2, s.gamma1);
    comFr(p.combeta2, s.sbeta2, pp.v1, pp.v2, s.beta2);
    comFr(p.comgamma2, s.sgamma2, pp.v1, pp.v2, s.gamma2); //Commitments to secrets
            
    //Proof ct1 = g^sk . Pw1^beta1 . L^gamma1
    p.theta1 = pp.G*s.ssk + pp.Pw1*s.sbeta1 + pp.L*s.sgamma1;
    
    //Proof ct2 = g^sk . Pw2^beta2 . L^gamma2
    p.theta7 = pp.G*s.ssk + pp.Pw2*s.sbeta2 + pp.L*s.sgamma2;

    //Proof Q1 = M^beta1 . G^gamma1 
    p.theta2 = pp.M*s.sbeta1 + pp.G*s.sgamma1;
    
    //Proof Q2 = M^beta2 . G^gamma2
    p.theta8 = pp.M*s.sbeta2 + pp.G*s.sgamma2;
    
    //Proof g^sk . pk^-1 = 1
    Tt[0].setRand(); Tt[1].setRand();

    p.pi3[0][0] = pp._i2[0]*(s.rpk[0]) - (pp.v1[0]*Tt[0]);
    p.pi3[0][1] = pp._i2[1]*(s.rpk[0]) - (pp.v1[1]*Tt[0]);
    p.pi3[1][0] = pp._i2[0]*(s.rpk[1]) - (pp.v1[0]*Tt[1]);
    p.pi3[1][1] = pp._i2[1]*(s.rpk[1]) - (pp.v1[1]*Tt[1]);
    
    p.theta3[0] = pp.u1[0]*Tt[0] + pp.u2[0]*Tt[1];
    p.theta3[1] = pp.u1[1]*Tt[0] + pp.u2[1]*Tt[1] + pp.G*s.ssk;
    
    //Proof e(F,D).e(C,H^-1) = 1        
    TT[0][0].setRand();
    TT[0][1].setRand();
    TT[1][0].setRand();
    TT[1][1].setRand();

    comG1(p.comA, s.rA, pp.u1, pp.u2, s.A);
    comG1(p.comC, s.rC, pp.u1, pp.u2, s.C);
    comG1(p.comR, s.rR, pp.u1, pp.u2, s.R);
    comG2(p.comD, s.sD, pp.v1, pp.v2, s.D);
    comG2(p.comS, s.sS, pp.v1, pp.v2, s.S);
    
    p.theta4[0][0] = pp.u1[0]*TT[0][0] + pp.u2[0]*TT[1][0];
    p.theta4[1][0] = pp.u1[0]*TT[0][1] + pp.u2[0]*TT[1][1];
    p.theta4[0][1] = pp.u1[1]*TT[0][0] + pp.u2[1]*TT[1][0] + pp.F*s.sD[0];
    p.theta4[1][1] = pp.u1[1]*TT[0][1] + pp.u2[1]*TT[1][1] + pp.F*s.sD[1];

    p.pi4[0][0] = -(pp.v1[0]*TT[0][0] + pp.v2[0]*TT[0][1]);
    p.pi4[1][0] = -(pp.v1[0]*TT[1][0] + pp.v2[0]*TT[1][1]);
    p.pi4[0][1] = pp.Hinv*s.rC[0] - (pp.v1[1]*TT[0][0] + pp.v2[1]*TT[0][1]);
    p.pi4[1][1] = pp.Hinv*s.rC[1] - (pp.v1[1]*TT[1][0] + pp.v2[1]*TT[1][1]);       

    //Proof e(G,S),e(R,H^-1) = 1
    TT[0][0].setRand();
    TT[0][1].setRand();
    TT[1][0].setRand();
    TT[1][1].setRand();

    p.theta5[0][0] = pp.u1[0]*TT[0][0] + pp.u2[0]*TT[1][0];
    p.theta5[1][0] = pp.u1[0]*TT[0][1] + pp.u2[0]*TT[1][1];
    p.theta5[0][1] = pp.u1[1]*TT[0][0] + pp.u2[1]*TT[1][0] + pp.G*s.sS[0];
    p.theta5[1][1] = pp.u1[1]*TT[0][1] + pp.u2[1]*TT[1][1] + pp.G*s.sS[1];

    p.pi5[0][0] = -(pp.v1[0]*TT[0][0] + pp.v2[0]*TT[0][1]);
    p.pi5[1][0] = -(pp.v1[0]*TT[1][0] + pp.v2[0]*TT[1][1]);
    p.pi5[0][1] = pp.Hinv*s.rR[0] - (pp.v1[1]*TT[0][0] + pp.v2[1]*TT[0][1]);
    p.pi5[1][1] = pp.Hinv*s.rR[1] - (pp.v1[1]*TT[1][0] + pp.v2[1]*TT[1][1]);  
    
    //Proof e(A,Y).e(A,D).e(K^-1,id).e(K^-1,H).e(T^-1,S) = 1
    TT[0][0].setRand();
    TT[0][1].setRand();
    TT[1][0].setRand();
    TT[1][1].setRand();

    TT[0][0]=0;
    TT[0][1]=0;
    TT[1][0]=0;
    TT[1][1]=0;

    Fr RS[2][2];
    RS[0][0]= s.rA[0]*s.sD[0];
    RS[0][1]= s.rA[0]*s.sD[1];
    RS[1][0]= s.rA[1]*s.sD[0];
    RS[1][1]= s.rA[1]*s.sD[1];

    p.theta6[0][0] = pp.u1[0]*TT[0][0] + pp.u2[0]*TT[1][0];
    p.theta6[1][0] = pp.u1[0]*TT[0][1] + pp.u2[0]*TT[1][1];
    p.theta6[0][1] = pp.u1[1]*TT[0][0] + pp.u2[1]*TT[1][0] + pp.Tinv*s.sS[0] + s.A*s.sD[0];
    p.theta6[1][1] = pp.u1[1]*TT[0][1] + pp.u2[1]*TT[1][1] + pp.Tinv*s.sS[1] + s.A*s.sD[1];
    
    p.pi6[0][0] = pp.v1[0]*(RS[0][0] - TT[0][0]) + pp.v2[0]*(RS[0][1] - TT[0][1]);
    p.pi6[1][0] = pp.v1[0]*(RS[1][0] - TT[1][0]) + pp.v2[0]*(RS[1][1] - TT[1][1]);
    p.pi6[0][1] = pp.v1[1]*(RS[0][0] - TT[0][0]) + pp.v2[1]*(RS[0][1] - TT[0][1]) + pp.Hinv*s.rpk[0] + pp.Y*s.rA[0] + s.D*s.rA[0];
    p.pi6[1][1] = pp.v1[1]*(RS[1][0] - TT[1][0]) + pp.v2[1]*(RS[1][1] - TT[1][1]) + pp.Hinv*s.rpk[1] + pp.Y*s.rA[1] + s.D*s.rA[1];
}

bool SPCver(proof const &p, publicparam const &pp){
    //Verifies the set pre-constrained group signature.
    Fp12 lhs,ttemp,rhs;
    bool flag=false;
    //Constraint 1 
    //Equation 3
    lhs = e(pp.G, p.comsk[0])*e(pp.Pw1, p.combeta1[0])*e(pp.L, p.comgamma1[0]);
    rhs = e(pp.ct1, pp.v[0])*e(p.theta1, pp.v1[0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 4
    lhs = e(pp.G, p.comsk[1])*e(pp.Pw1, p.combeta1[1])*e(pp.L, p.comgamma1[1]);
    rhs = e(pp.ct1, pp.v[1])*e(p.theta1, pp.v1[1]);

    if(!(lhs==rhs))
        flag=true;

    //Constraint 2
    //Equation 3
    lhs = e(pp.M, p.combeta1[0])*e(pp.G, p.comgamma1[0]);
    rhs = e(pp.Q1, pp.v[0])*e(p.theta2, pp.v1[0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 4
    lhs = e(pp.M, p.combeta1[1])*e(pp.G, p.comgamma1[1]);
    rhs = e(pp.Q1, pp.v[1])*e(p.theta2, pp.v1[1]);

    if(!(lhs==rhs))
        flag=true;
    
    //Constraint 3
    //Equation 1
    lhs = e(p.compk[0], pp._i2[0]);
    rhs = e(pp.u1[0], p.pi3[0][0])*e(pp.u2[0], p.pi3[1][0])*e(p.theta3[0], pp.v1[0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Constraint 3
    //Equation 2
    lhs = e(p.compk[0], pp._i2[1]);
    rhs = e(pp.u1[0], p.pi3[0][1])*e(pp.u2[0], p.pi3[1][1])*e(p.theta3[0], pp.v1[1]);
    
    if(!(lhs==rhs))
        flag=true;
    
    //Constraint 3
    //Equation 3
    lhs = e(pp.G, p.comsk[0])*e(p.compk[1], pp._i2[0]);
    rhs = e(pp.u1[1], p.pi3[0][0])*e(pp.u2[1], p.pi3[1][0])*e(p.theta3[1], pp.v1[0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Constraint 3
    //Equation 4
    lhs = e(pp.G, p.comsk[1])*e(p.compk[1], pp._i2[1]);
    rhs = e(pp.u1[1], p.pi3[0][1])*e(pp.u2[1], p.pi3[1][1])*e(p.theta3[1], pp.v1[1]);

    //Constraint 4
    //Equation 1
    rhs = e(p.theta4[0][0], pp.v1[0])*e(p.theta4[1][0], pp.v2[0])*e(pp.u1[0], p.pi4[0][0])*e(pp.u2[0], p.pi4[1][0]);

    if(!(pp.idT==rhs))
        flag = true;
    
    //Equation 2
    lhs = e(p.comC[0], pp.Hinv);
    rhs = e(pp.u1[0], p.pi4[0][1])*e(pp.u2[0], p.pi4[1][1])*e(p.theta4[0][0],pp.v1[1])*e(p.theta4[1][0],pp.v2[1]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 3
    lhs = e(pp.F, p.comD[0]);
    rhs = e(p.theta4[0][1], pp.v1[0])*e(p.theta4[1][1], pp.v2[0])*e(pp.u1[1],p.pi4[0][0])*e(pp.u2[1],p.pi4[1][0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 4
    lhs = e(pp.F, p.comD[1])*e(p.comC[1], pp.Hinv);
    rhs = e(pp.u1[1],p.pi4[0][1])*e(pp.u2[1],p.pi4[1][1])*e(p.theta4[0][1], pp.v1[1])*e(p.theta4[1][1], pp.v2[1]);

    if(!(lhs==rhs))
        flag=true;
    
    
    //Constraint 5
    //Equation 1
    rhs = e(p.theta5[0][0], pp.v1[0])*e(p.theta5[1][0], pp.v2[0])*e(pp.u1[0], p.pi5[0][0])*e(pp.u2[0], p.pi5[1][0]);

    if(!(pp.idT==rhs))
        flag = true;
    
    //Equation 2
    lhs = e(p.comR[0], pp.Hinv);
    rhs = e(pp.u1[0], p.pi5[0][1])*e(pp.u2[0], p.pi5[1][1])*e(p.theta5[0][0],pp.v1[1])*e(p.theta5[1][0],pp.v2[1]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 3
    lhs = e(pp.G, p.comS[0]);
    rhs = e(p.theta5[0][1], pp.v1[0])*e(p.theta5[1][1], pp.v2[0])*e(pp.u1[1],p.pi5[0][0])*e(pp.u2[1],p.pi5[1][0]);
    
    if(!(lhs==rhs))
        flag=true;
    
    //Equation 4
    lhs = e(pp.G, p.comS[1])*e(p.comR[1], pp.Hinv);
    rhs = e(pp.u1[1],p.pi5[0][1])*e(pp.u2[1],p.pi5[1][1])*e(p.theta5[0][1], pp.v1[1])*e(p.theta5[1][1], pp.v2[1]);

    if(!(lhs==rhs))
        flag=true;


    //Constraint 6        
    //Equation 1
    lhs = e(p.comA[0], p.comD[0]);
    rhs = e(p.theta6[0][0], pp.v1[0])*e(p.theta6[1][0], pp.v2[0])*e(pp.u1[0], p.pi6[0][0])*e(pp.u2[0], p.pi6[1][0]);

    if(!(lhs==rhs))
        flag = true;
    
    //Equation 2
    lhs = e(p.comA[0], pp.Y)*e(p.compk[0], pp.Hinv)*e(p.comA[0], p.comD[1]);
    rhs = e(pp.u1[0], p.pi6[0][1])*e(pp.u2[0], p.pi6[1][1])*e(p.theta6[0][0],pp.v1[1])*e(p.theta6[1][0],pp.v2[1]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 3
    lhs = e(pp.Tinv, p.comS[0])*e(p.comA[1], p.comD[0]);
    rhs = e(pp.u1[1], p.pi6[0][0])*e(pp.u2[1], p.pi6[1][0])*e(p.theta6[0][1],pp.v1[0])*e(p.theta6[1][1],pp.v2[0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 4
    lhs = e(pp.Tinv, p.comS[1])*e(p.comA[1], p.comD[1])*e(p.comA[1], pp.Y)*e(p.compk[1], pp.Hinv);
    rhs = e(pp.u1[1], p.pi6[0][1])*e(pp.u2[1], p.pi6[1][1])*e(p.theta6[0][1],pp.v1[1])*e(p.theta6[1][1],pp.v2[1])*e(pp.K,pp.H);

    if(!(lhs==rhs))
        flag=true;
    
    //Constraint 7
    lhs = e(pp.G, p.comsk[0])*e(pp.Pw2, p.combeta2[0])*e(pp.L, p.comgamma2[0]);
    rhs = e(pp.ct2, pp.v[0])*e(p.theta7, pp.v1[0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 4
    lhs = e(pp.G, p.comsk[1])*e(pp.Pw2, p.combeta2[1])*e(pp.L, p.comgamma2[1]);
    rhs = e(pp.ct2, pp.v[1])*e(p.theta7, pp.v1[1]);

    if(!(lhs==rhs))
        flag=true;
    
    //Constraint 8
    //Equation 3
    lhs = e(pp.M, p.combeta2[0])*e(pp.G, p.comgamma2[0]);
    rhs = e(pp.Q2, pp.v[0])*e(p.theta8, pp.v1[0]);

    if(!(lhs==rhs))
        flag=true;
    
    //Equation 4
    lhs = e(pp.M, p.combeta2[1])*e(pp.G, p.comgamma2[1]);
    rhs = e(pp.Q2, pp.v[1])*e(p.theta8, pp.v1[1]);

    if(!(lhs==rhs))
        flag=true;
    
    return flag;
}

void setup(publicparam &pp){
    //Setup for the set pre-constrained group signature scheme
    mapToG1(pp.G,1);  mapToG2(pp.H, 1); //Generator    
    pp.id1 = pp.G*0;
    pp.id2 = pp.H*0;
    pairing(pp.idT, pp.id1, pp.id2);
    Hash(pp.M, pp.m); //Hashing to a group element

    setRandG1(pp.P1, pp.G);
    setRandG2(pp.P2, pp.H);

    gencomkey(pp.u1, pp.u2, pp.P1);
    gencomkey(pp.v1, pp.v2, pp.P2);

    pp.u[0] = pp.u2[0];
    pp.u[1] = pp.u2[1];
    pp.u[1] = pp.u[1] + pp.P1; //u=(t1P1, t1Q1+P1) -- this is a different Q see Groth-Sahai
    pp.v[0] = pp.v2[0];
    pp.v[1] = pp.v2[1];
    pp.v[1] = pp.v[1] + pp.P2; //v=(t2P2, t2Q2+P2) -- this is a different Q see Groth-Sahai

    pp._i2[0] = pp.v[0]*(-1);
    pp._i2[1] = pp.v[1]*(-1);
}