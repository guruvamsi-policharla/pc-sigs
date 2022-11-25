#pragma once

#define curveid 4

#ifndef curveid
#define curveid 1
#endif

#if curveid == 1
#include <mcl/bn256.hpp>
using namespace mcl::bn256;
#elif curveid == 2
#include <mcl/bn384.hpp>
using namespace mcl::bn384;
#elif curveid == 3
#include <mcl/bn512.hpp>
using namespace mcl::bn512;
#elif curveid == 4
#include <mcl/bls12_381.hpp>
using namespace mcl::bls12;
#else
#error "Invalid choice for curve."
#endif


struct proof{
    //Groth-Sahai proof attached as part of the set pre-constrained group signature. Number of variables may seem cumbersome but this helps with understanding logic in the code.
    G2 combeta1[2], comgamma1[2], combeta2[2], comgamma2[2], comsk[2];
    G1 theta1, theta2, theta7, theta8;
};

struct secrets{
    //Secrets which will be committed to as part of the set pre-constrained group signature.
    Fr sk, beta1, gamma1, beta2, gamma2, sbeta1, sgamma1, sbeta2, sgamma2, ssk;
    G1 pk;
};

struct publicparam{
    //Public paramters in the entire construction
    G1 G, hG, Pw1, Pw2, L, ct1, ct2, M, Q1, Q2, u1[2], u2[2], u[2], P1;
    G2 H, v1[2], v2[2], v[2], P2, _i2[2];
    std::string m;
};

GT e(const G1&, const G2&);

void gencomkey(G1* u1, G1* u2, const G1& P1);
void gencomkey(G2* v1, G2* v2, const G2& P2);

void comG1(G1* com, Fr* r, G1* u1, G1* u2, const G1& m);
void comG2(G2* com, Fr* s, G2* v1, G2* v2, const G2& m);

void comFr(G1* com, Fr& r, G1* u1, G1* u2, const Fr& m);
void comFr(G2* com, Fr& r, G2* v1, G2* v2, const Fr& m);

void Hash(G1& P, const std::string& m);

void setRandG1(G1& op, const G1& G);
void setRandG2(G2& op, const G2& H);

void SPCEnc(proof &p, secrets &s, publicparam &pp);
void SPCsign(proof &p, secrets &s, publicparam &pp);
bool SPCver(proof const &p, publicparam const &pp);

void setup(publicparam &pp);