#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <algorithm>

#include <omp.h>

#include <openfhe.h>
#include <openfhecore.h>

#include "include/basics.hpp"
#include "include/mfbr.hpp"
// #include "include/fbs.hpp"

using namespace std;
using namespace lbcrypto;



const string MFIPTABLE = "../lookupTables/MFIP_nB_3_dQ_0.001_dimF_512.txt";
const string FBORDERS = "../lookupTables/Borders_nB_3_dimF_512.txt";
const string SAMPLESDIR = "../data/VGGFace2/ArcFace-R100/ArcFace-R100_";
const size_t NROWS = 8;
const int NFEAT = 512;
const int COMPLEN = 794; // Smax-threshold+1=926-133+1
const int64_t THRESHOLD = 133; // threshold @0.1%FMR with a TMR of 97.1%
const int SEED = 45676;

int main(int argc, char *argv[]) {
    

    double toc;
    TimeVar t;
    string sBits = argv[1]; 
    int multDepth(0); 
    int start = stoi(argv[2]);
    int end = stoi(argv[3]);




    string mode;  
    if (stoi(argv[4]) == 0)
    {
        mode = "CleartextDecision";
        multDepth = 1;
    }
    else if (stoi(argv[4]) == 1)
    {
        mode = "EncryptedDecision";
        multDepth = 2;
    }
    else
    {
        cout << "Choose one of the following search modes: 0: Cleartext Decision or 1: Encrypted Decision" << endl;
    }    



    string mainDir("../results/experimentsMFIPV2-BFVrns/MFIP-"+mode);
    createNestedDirs(mainDir);


    string referenceTempSTR = mainDir+"/reference-MFIPv2-"+sBits+".txt";
    string probeTempSTR = mainDir+"/probe-MFIPv2-"+sBits+".txt";

    string enrollRuntime = mainDir+"/expMFIP-Enrollment-"+sBits+".csv";
    string verificationRuntime = mainDir+"/expMFIP-Verification-"+sBits+".csv";

    string refTempGenRuntime = mainDir+"/expMFIP-permRefTempGen-"+sBits+".csv";
    string probTempGenRuntime = mainDir+"/expMFIP-probTempGen-"+sBits+".csv";



    cout << "Security "+sBits+" bits"<< endl;




 





    int64_t nBits(16);  
    uint64_t m(32768);
    auto plaintextMod = FirstPrime<NativeInteger>(nBits, m);
    usint plaintextModulus = (usint) plaintextMod.ConvertToInt();




     

    CCParams<CryptoContextBFVRNS> parameters;
    SecurityLevel securityLevel;  
    double statisticalSecurity;  
    usint multiplicativeDepth(multDepth); 
    usint dcrtBits(0);

    if (sBits == "128")
    {
        securityLevel = HEStd_128_classic;
        statisticalSecurity = 128/2;
        dcrtBits = 36;
    }
    if (sBits == "192")
    {
        securityLevel = HEStd_192_classic;
        statisticalSecurity = 192/2;
        dcrtBits = 37;
    }
    if (sBits == "256")
    {
        securityLevel = HEStd_256_classic;
        statisticalSecurity = 256/2;
        dcrtBits = 38; 
    } 


    parameters.SetFirstModSize(dcrtBits);
    parameters.SetStatisticalSecurity(statisticalSecurity);  

    parameters.SetSecurityLevel(securityLevel);  
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);
    if(multDepth != 1)
    {
        parameters.SetMaxRelinSkDeg(multiplicativeDepth);
    }




    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);


    cout << "parameters = \n" << parameters << endl;




    KeyPair<DCRTPoly> keyPair;
    keyPair = cryptoContext->KeyGen();    

    if (!keyPair.good()) {
        cout << "Key generation failed!" << endl;
        exit(1);
    }
    else
    {
        cout << "Key generation successful!" << endl;
    }

    PrivateKey<DCRTPoly> secretKey = keyPair.secretKey;
    PublicKey<DCRTPoly> publicKey = keyPair.publicKey;

    auto ringDim = cryptoContext->GetRingDimension();
    cout << "ringDim = " << ringDim << endl;


    cryptoContext->EvalSumKeyGen(keyPair.secretKey);
    cryptoContext->EvalMultKeysGen(secretKey);

    auto shiftIndexes = genVectOfPowOf2(log2(ringDim)+1);
    cryptoContext->EvalRotateKeyGen(secretKey, shiftIndexes);

    


    cout << "Keys successfully generated ..." << endl; 

    
    // Loading borders and the MFIP lookup table
    auto borders = readLineDouble(FBORDERS);
    auto tabMFIP = readTableInt64(MFIPTABLE, NROWS);

    Plaintext compVectPT, blindRPT; 
    Ciphertext<DCRTPoly> compVectCT;
    vector<int64_t> compVect;

    if (stoi(argv[4]) == 1)
    {
        // For the encrypted comparison with the threshold: generate the permuted comparison vector and the blinding vector
        auto vectR = genRandVectOfInt64(1, (int64_t) plaintextModulus/4-1, COMPLEN);
        blindRPT = cryptoContext->MakePackedPlaintext(vectR);
        compVect = vectIntPermutationInt64Neg(SEED, THRESHOLD, COMPLEN);
        compVectPT = cryptoContext->MakePackedPlaintext(compVect);
        compVectCT = cryptoContext->Encrypt(publicKey, compVectPT);
    }


    for (int subject = start; subject < end+1; subject++)
    {
        /////////////////////
        // Enrollment Phase
        /////////////////////  

        string rawRefFile = SAMPLESDIR+to_string(subject)+"_1.txt";
        auto rawRef = readLineDouble(rawRefFile);
        auto permutations = genPermutationsConcat(SEED, NFEAT, NROWS);
        auto permutationsInverse = getPermutationsInverse(permutations);
        auto quantizedRef = quantizeFeatures(borders, rawRef);
        auto refTemp = refTemplate(quantizedRef, tabMFIP);


        TIC(t);
        auto permRefTempCT = encryptPermutedRefTempSingleCT(publicKey, refTemp, permutations);
        toc = TOC_MS(t);
        writeProcTime(refTempGenRuntime, toc);
        cout << "Permuted reference template is encrypted, it took "<< toc << "ms" << endl;



        /////////////////////
        // Verification Phase
        /////////////////////  

        string rawProbeFile = SAMPLESDIR+to_string(subject)+"_2.txt";
        auto rawProbe = readLineDouble(rawProbeFile); 
        auto quantizedProb = quantizeFeatures(borders, rawProbe);  
        

        TIC(t);          
        auto permProbeTemp = genPermProbeTemplateFromPermInv(quantizedProb, permutationsInverse, NROWS);
        auto permProbeTempMask = getPermutedProbeTempMask(permProbeTemp, ringDim);
        toc = TOC_MS(t);
        writeProcTime(probTempGenRuntime, toc);
        cout << "Generation of the permuted probe template took "<< toc << "ms" << endl;

        if(subject == start)
        {
            saveInBinaryFile(referenceTempSTR, permRefTempCT);
            saveInBinaryFile(probeTempSTR, permProbeTemp);
        }



        if (mode == "CleartextDecision")
        { 
            TIC(t);            
            auto finalScoreCT = getFinalScoreCT(permRefTempCT, permProbeTempMask);
            auto finalScore = revealFinalScores(secretKey, finalScoreCT);
            auto verifyRes = (finalScore[0]<THRESHOLD) ? "No Match": "Match";
            toc = TOC_MS(t);
            writeProcTime(verificationRuntime, toc);
            cout << "Verification of subject " << subject << " is a " << verifyRes << endl;
            cout << "Verification took "<< toc << "ms" << endl;
        }
        if (mode == "EncryptedDecision")
        {
            TIC(t);            
            auto finalScoreCT = getFinalScoreCT(permRefTempCT, permProbeTempMask);            
            cryptoContext->EvalAddInPlace(finalScoreCT, compVectPT); 
            auto decisionCT = cryptoContext->EvalMult(finalScoreCT, blindRPT);

            Plaintext decisionPT;
            cryptoContext->Decrypt(secretKey, decisionCT, &decisionPT);  
            decisionPT->SetLength(COMPLEN);
            auto res = verifyComparisonBinaryTree(decisionPT->GetPackedValue());  
            string verifyRes = (res)? "Match" : "No Match";
            toc = TOC_MS(t);
            writeProcTime(verificationRuntime, toc);
            cout << "Verification of subject " << subject << " is a " << verifyRes << endl;
            cout << "Verification took "<< toc << "ms" << endl;          

        }





    }


    return 0;
}