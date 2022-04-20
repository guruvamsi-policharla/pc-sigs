#include "linkpcsig.h"

#if curveid == 1
#include <mcl/bn256.hpp>
using namespace mcl::bn256;
#elif curveid == 2
#include <mcl/bn384.hpp>
using namespace mcl::bn384;
#elif curveid == 3
#include <mcl/bn512.hpp>
using namespace mcl::bn512;
#else
#error "Invalid choice for curve."
#endif

#include<iostream>
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
    t1.setRand();
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
    t2.setRand();
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

void SPCsign(proof &p, secrets &s, publicparam &pp){
    //Constructs a Groth-Sahai proof satisfying necessary constraints for linkable set pre-constrained group signature scheme.
    
    //Constraint Creation
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
    Hash(pp.M, pp.m); //Hashing to a group element

    setRandG1(pp.P1, pp.G);
    setRandG2(pp.P2, pp.H);
    Hash(pp.hG, "input to random oracle here");

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