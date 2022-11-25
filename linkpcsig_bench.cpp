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
#elif curveid == 4
#include <mcl/bls12_381.hpp>
using namespace mcl::bls12;
#else
#error "Invalid choice for curve."
#endif

#include <iostream>
#include <chrono>

using namespace std;
using namespace std::chrono;

int main(int argc, char** argv){
    
    int N = 100; //Number of iterations to average over
    
    if(argc>1)
        N = atoi(argv[1]);

    cout<<"Averaging over "<<N<<" iterations"<<endl;
    
    switch(curveid) {
    case 1:
        cout<<"Using curve BN254"<<endl;
        initPairing(mcl::BN254); //Assuming SXDH holds in BN254
        break;
    case 2:
        cout<<"Using curve BN381_1"<<endl;
        initPairing(mcl::BN381_1); //Assuming SXDH holds in BN381_1
        break;
    case 3:
        cout<<"Using curve BN462"<<endl;
        initPairing(mcl::BN462); //Assuming SXDH holds in BN462
        break;
    default:
        std::perror("Invalid choice for curve.");
    }
        
    proof p;
    secrets s;
    publicparam pp;
    G1 pkopen1, pkopen2;

    if(argc>2)
        pp.m = argv[2];
    else
        pp.m = "hello world";
    
    cout<<"Creating an SPC group signature on \""<<pp.m<<"\""<<endl;
    //Setup
    setup(pp);

    //Creating client's public and secret key
    s.sk.setRand(); 
    s.pk = pp.G*s.sk; // pk = G^sk
    
    //ApplePSI secretkey
    Fr alpha;
    alpha.setRand();
    pp.L = pp.G*alpha; //L = G^alpha
    
   auto startenc = high_resolution_clock::now(), stopenc = high_resolution_clock::now(),
    startprove = high_resolution_clock::now(), stopprove = high_resolution_clock::now(), 
    startver = high_resolution_clock::now(), stopver = high_resolution_clock::now(), 
    startopen = high_resolution_clock::now(), endopen = high_resolution_clock::now();

    double enctotal = 0, provetotal = 0, verifytotal = 0, opentotal = 0;

    auto encduration = duration_cast<microseconds>(endopen - startopen),
    proveduration = duration_cast<microseconds>(stopprove - startprove), 
    verduration = duration_cast<microseconds>(stopver - startver), 
    openduration = duration_cast<microseconds>(endopen - startopen);

    bool flag=false;
    for(int i = 0; i<N;i++){ //Benchmarking loop

        startenc = high_resolution_clock::now();
        SPCEnc(p,s,pp);
        stopenc = high_resolution_clock::now();

        //Proving  
        startprove = high_resolution_clock::now();
        SPCsign(p, s, pp);
        stopprove = high_resolution_clock::now();

        //Verification
        startver = high_resolution_clock::now();
        flag = SPCver(p, pp);
        stopver = high_resolution_clock::now();

        if(flag)
            cout<<"fail"<<endl;

        //Opening
        startopen = high_resolution_clock::now();
        pkopen1 = pp.ct1 - (pp.Q1*alpha);
        pkopen2 = pp.ct2 - (pp.Q2*alpha);
        endopen = high_resolution_clock::now();
        
        encduration = duration_cast<microseconds>(stopenc - startenc);
        proveduration = duration_cast<microseconds>(stopprove - startprove);
        verduration = duration_cast<microseconds>(stopver - startver);
        openduration = duration_cast<microseconds>(endopen - startopen);

        enctotal = enctotal + encduration.count();
        provetotal = provetotal + proveduration.count();
        verifytotal = verifytotal + verduration.count();
        opentotal = opentotal + openduration.count();
    
    }

    cout<< "Mean enc time (\u03BCs):"<<enctotal/N<<endl;
    cout<< "Mean prove time (\u03BCs):"<<provetotal/N<<endl;
    cout<< "Mean verify time (\u03BCs):"<<verifytotal/N<<endl;
    cout<< "Mean open time (\u03BCs):"<<opentotal/N<<endl;
    
}

