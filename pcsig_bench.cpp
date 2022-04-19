#include <mcl/bn256.hpp>
#include "gs.h"
#include <iostream>
#include <chrono>

using namespace mcl::bn256;
using namespace std;
using namespace std::chrono;

int main(int argc, char** argv){
    
    int N = 100; //Number of iterations to average over
    
    if(argc>1)
        N = atoi(argv[1]);

    cout<<"Averaging over "<<N<<" iterations"<<endl;
    
    initPairing(mcl::BN254); //Assuming SXDH holds in BN254
    
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
    s.HG = pp.hG*s.sk; //HG = hG^sk
    
    //Receving AHO signature on public key from server
    Fr x;//AHO secret key
    AHOkeygen(pp.F, pp.K, pp.T, pp.X, pp.Y, x, pp.G, pp.H);
    AHOsign(s.A, s.C, s.D, s.R, s.S, pp.F, pp.T, pp.K, s.pk, pp.G, pp.H, x);
    //e(C,H) = e(F,D)
    //e(R,H) = e(G,S)
    //e(A,Y.D) = e(K.pk, H).e(T,S)
    
    //ApplePSI secretkey
    Fr alpha;
    alpha.setRand();
    pp.L = pp.G*alpha; //L = G^alpha
    
    auto startprove = high_resolution_clock::now(), stopprove = high_resolution_clock::now(), startver = high_resolution_clock::now(), stopver = high_resolution_clock::now(), 
    startopen = high_resolution_clock::now(), endopen = high_resolution_clock::now();

    double provetotal = 0, verifytotal = 0, opentotal = 0;

    auto proveduration = duration_cast<microseconds>(stopprove - startprove), verduration = duration_cast<microseconds>(stopver - startver), openduration = duration_cast<microseconds>(endopen - startopen);

    bool flag=false;
    for(int i = 0; i<N;i++){ //Benchmarking loop
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
        
        proveduration = duration_cast<microseconds>(stopprove - startprove);
        //cout << "Prove time:"<<proveduration.count() << endl;
        //cout<<proveduration.count() << endl;
        verduration = duration_cast<microseconds>(stopver - startver);
        //cout << "Verify time:"<<verduration.count() << endl;
        // cout<<verduration.count() << endl;
        openduration = duration_cast<microseconds>(endopen - startopen);
        //cout<<"open time:"<<openduration.count()<<endl;
        //cout<<openduration.count()<<endl;

        provetotal = provetotal + proveduration.count();
        verifytotal = verifytotal + verduration.count();
        opentotal = opentotal + openduration.count();
    
    }

    cout<< "Mean prove time (\u03BCs):"<<provetotal/N<<endl;
    cout<< "Mean verify time (\u03BCs):"<<verifytotal/N<<endl;
    cout<< "Mean open time (\u03BCs):"<<opentotal/N<<endl;
    
}

