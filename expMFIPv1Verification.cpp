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
const int NEVALKEY = 8; 
const size_t NROWS = 8;
const int NFEAT = 512;
const int COMPLEN = 794; // Smax-threshold+1=926-133+1
const int64_t THRESHOLD = 133; // threshold @0.1%FMR with a TMR of 97.1%
const int SEED = 45676;
const int NCIPHERS = (int) NROWS*NFEAT;


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



    string mainDir("../results/experimentsMFIPV1-BFVrns/MFIP-"+mode);
    createNestedDirs(mainDir);

    string referenceTempSTR = mainDir+"/reference-MFIPv1-"+sBits+".txt";
    string probeTempSTR = mainDir+"/probe-MFIPv1-"+sBits+".txt";

    string enrollRuntime = mainDir+"/expMFIP-Enrollment-"+sBits+".csv";
    string verificationRuntime = mainDir+"/expMFIP-Verification-"+sBits+".csv";

    string refTempGenRuntime = mainDir+"/expMFIP-permRefTempGen-"+sBits+".csv";
    string probTempGenRuntime = mainDir+"/expMFIP-probTempGen-"+sBits+".csv";



    cout << "Security "+sBits+" bits" << endl;




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
        dcrtBits = (stoi(argv[4]) == 0) ? 36: 39;
    }
    if (sBits == "192")
    {
        securityLevel = HEStd_192_classic;
        statisticalSecurity = 192/2;
        dcrtBits = (stoi(argv[4]) == 0) ? 37: 39;
    }
    if (sBits == "256")
    {
        securityLevel = HEStd_256_classic;
        statisticalSecurity = 256/2;
        dcrtBits = (stoi(argv[4]) == 0) ? 38: 39; 
    } 

    parameters.SetFirstModSize(dcrtBits);

    parameters.SetSecurityLevel(securityLevel);
    parameters.SetStatisticalSecurity(statisticalSecurity);    
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
    size_t halfRing = (size_t) ringDim/2;
    cout << "ringDim = " << ringDim << endl;


    cryptoContext->EvalSumKeyGen(keyPair.secretKey);
    cryptoContext->EvalMultKeysGen(secretKey);

    auto shiftIndexes = genVectOfInt(1, NEVALKEY); 
    if (stoi(argv[4]) == 1)
    {
        auto pow2Vect = genVectOfPowOf2(log2(halfRing)+1);
        shiftIndexes.insert(shiftIndexes.end(), pow2Vect.begin(), pow2Vect.end());  
    }
    cryptoContext->EvalRotateKeyGen(secretKey, shiftIndexes);

    


    cout << "Keys successfully generated ..." << endl; 

    
    // Loading borders and the MFIP lookup table
    auto borders = readLineDouble(FBORDERS);
    auto tabMFIP = readTableInt64(MFIPTABLE, NROWS);

    size_t nPackedRowsPerCipher = (size_t) NEVALKEY/NROWS;
    size_t numCiphers = (size_t) (NFEAT * NROWS)/NEVALKEY;

    cout << "numCiphers = " << numCiphers << "; nPackedRowPerCipher = " << nPackedRowsPerCipher << endl;

    Plaintext compVectPT, blindRPT, onePlain; 
    Ciphertext<DCRTPoly> blindRCT;
    // , compVectCT;
    vector<int64_t> compVect;

    if (stoi(argv[4]) == 0)
    {
        // For isolating the first plaintext slot 
        auto vectR = genRandVectOfInt64(1, (int64_t) plaintextModulus/4-1, ringDim);
        vectR.at(0) = 0;
        blindRPT = cryptoContext->MakePackedPlaintext(vectR);
        blindRCT = cryptoContext->Encrypt(keyPair.publicKey, blindRPT);
    }
    
    if (stoi(argv[4]) == 1)
    {
        // For the encrypted comparison with the threshold: generate the permuted comparison vector and the blinding vector
        auto vectR = genRandVectOfInt64(1, (int64_t) plaintextModulus/4-1, COMPLEN);
        blindRPT = cryptoContext->MakePackedPlaintext(vectR);
        auto compVect = vectIntPermutationInt64Neg(SEED, THRESHOLD, COMPLEN);
        compVectPT = cryptoContext->MakePackedPlaintext(compVect);
        onePlain = cryptoContext->MakePackedPlaintext({1,0});
    }



    for (int subject = start; subject < end+1; subject++)
    {
        /////////////////////
        // Enrollment Phase
        /////////////////////  

        
        auto permutations = genPermutations(SEED, numCiphers, NEVALKEY);

        string rawRefFile = SAMPLESDIR+to_string(subject)+"_1.txt";
        auto rawRef = readLineDouble(rawRefFile);
        auto quantizedRef = quantizeFeatures(borders, rawRef);
        auto refTempPacked = packRefTemplate2(quantizedRef, tabMFIP, nPackedRowsPerCipher, numCiphers);
            

        TIC(t);
        auto permRefTempCT = genEncryptedReferenceTemplate(cryptoContext, keyPair, refTempPacked, permutations);
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
        auto permProbInd = genPackedProbeIndexes(quantizedProb, permutations, nPackedRowsPerCipher, NROWS);
        toc = TOC_MS(t);
        writeProcTime(probTempGenRuntime, toc);
        cout << "Generation of the permuted probe template took "<< toc << "ms" << endl;
        
        if(subject == start)
        {
            saveInBinaryFile(referenceTempSTR, permRefTempCT);
            saveInBinaryFile(probeTempSTR, permProbInd);
        }
        


        if (mode == "CleartextDecision")
        { 
            TIC(t);            
            auto finalScoreCT = computeFinalScoreMFBRClearComp(cryptoContext, permRefTempCT, permProbInd, blindRCT, nPackedRowsPerCipher, NROWS);
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
            auto finalScoreCT0 = computeFinalScoreForBlindedCompGroups(cryptoContext, permRefTempCT, permProbInd, onePlain);

            // replicate the final score 'S' over all plaintext slots to get (S, S, ..., S)        
            Ciphertext<DCRTPoly> finalScoreCT = finalScoreCT0;       
            for (size_t i = 0; i < log2(halfRing); i++)
            {
                finalScoreCT0 = cryptoContext->EvalRotate(finalScoreCT, pow(2,i)); 
                cryptoContext->EvalAddInPlace(finalScoreCT, finalScoreCT0);
            }
            
            
            // compute the blinded comparison vector (.., (S-theta_{i})*r_{i}, ...)_{i} 
            // where theta_{i} \in [T, Smax] and r_{i} is rand used for the blinding 
                       
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