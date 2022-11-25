#pragma once

#define curveid 2

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
    G2 combeta1[2], comgamma1[2], combeta2[2], comgamma2[2], comsk[2], comD[2], comS[2], pi3[2][2], pi4[2][2], pi5[2][2], pi6[2][2], pi9[2][2];
    G1 comA[2], comC[2], comR[2], compk[2], comHG[2], theta1, theta2, theta3[2], theta4[2][2], theta5[2][2], theta6[2][2], theta7, theta8, theta9[2];
};

struct secrets{
    //Secrets which will be committed to as part of the set pre-constrained group signature.
    Fr sk, beta1, gamma1, beta2, gamma2, sbeta1, sgamma1, sbeta2, sgamma2, ssk, rpk[2], rHG[2], rA[2], rC[2], rR[2], sD[2], sS[2];
    G1 A, C, R, pk, HG;
    G2 D, S;
};

struct publicparam{
    //Public paramters in the entire construction
    G1 G, hG, Pw1, Pw2, L, ct1, ct2, M, Q1, Q2, F, K, T, X, id1, u1[2], u2[2], u[2], P1, Tinv, Kinv;
    G2 H, Y, v1[2], v2[2], v[2], P2, _i2[2], id2, Hinv;
    Fp12 idT;
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

void AHOkeygen(G1& F, G1& K, G1& T, G1& X, G2& Y, Fr& x, const G1& G, const G2& H);
void AHOsign(G1& A, G1& C, G2& D, G1& R, G2& S, const G1& F, const G1& T, const G1& K, const G1& M, const G1& G, const G2& H, const Fr& x);

void SPCEnc(proof &p, secrets &s, publicparam &pp);
void SPCsign(proof &p, secrets &s, publicparam &pp);
bool SPCver(proof const &p, publicparam const &pp);

void setup(publicparam &pp);