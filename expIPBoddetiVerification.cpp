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

const string SAMPLESDIR = "../data/VGGFace2/ArcFace-R100/ArcFace-R100_";
const string FBORDERS = "../lookupTables/Borders_nB_3_dimF_512.txt";
const int NFEAT = 512;
const int64_t THRESHOLD = 20000;
const size_t COMPLEN = 308171;
const int SEED = 45676;



int main(int argc, char *argv[]) {

    double toc;
    TimeVar t;
    string sBits = argv[1]; 
    int multDepth(2); 
    int start = stoi(argv[2]);
    int end = stoi(argv[3]);
    
    int precision = 400; // 0.0025


    string mode;  
    if (stoi(argv[4]) == 0)
    {
        mode = "CleartextDecision";
        // multDepth = 1;
    }
    else if (stoi(argv[4]) == 1)
    {
        mode = "EncryptedDecision";
    }
    else
    {
        cout << "Choose one of the following search modes: 0: Cleartext Decision or 1: Encrypted Decision" << endl;
    }    



    string mainDir("../results/experimentsIPBoddeti-BFVrns/IPBoddeti-"+mode);
    createNestedDirs(mainDir);
    
    string referenceTempSTR = mainDir+"/reference-IPBoddeti-"+sBits+".txt";
    string probeTempSTR = mainDir+"/probe-IPBoddeti-"+sBits+".txt";
    
    string enrollRuntime = mainDir+"/expIPBoddeti-Enrollment-"+sBits+".csv";
    string verificationRuntime = mainDir+"/expIPBoddeti-Verification-"+sBits+".csv";

    string refTempGenRuntime = mainDir+"/expIPBoddeti-permRefTempGen-"+sBits+".csv";
    string probTempGenRuntime = mainDir+"/expIPBoddeti-probTempGen-"+sBits+".csv";



    cout << "Security "+sBits+" bits" << endl;

    int64_t nBits(20);  
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
    cout << "ringDim = " << ringDim << endl;
    size_t row_size = (size_t) ringDim/2; 


   
    cryptoContext->EvalMultKeysGen(secretKey);
    cryptoContext->EvalSumKeyGen(secretKey); 


    auto shiftIndexes = genVectOfPowOf2(log2(ringDim)+1);
    cryptoContext->EvalRotateKeyGen(secretKey, shiftIndexes);

    cout << "Keys successfully generated ..." << endl; 


    Plaintext compVectPT, blindRPT; 
    Ciphertext<DCRTPoly> blindRCT;
    vector<Ciphertext<DCRTPoly>> compVectTCs;

    if (stoi(argv[4]) == 1)
    {
        // For the encrypted comparison with the threshold: generate the permuted comparison vector and the blinding vector
        auto vectR = genRandVectOfInt64(1, (int64_t) plaintextModulus/4-1, row_size);
        blindRPT = cryptoContext->MakePackedPlaintext(vectR);
        blindRCT = cryptoContext->Encrypt(publicKey, blindRPT);        
        
        for (size_t i = 0; i < COMPLEN; i = i+row_size)
        {
            auto compVect = vectIntPermutationInt64Neg(SEED, THRESHOLD+(int64_t)i, row_size);
            compVectPT = cryptoContext->MakePackedPlaintext(compVect);
            auto compVectCT = cryptoContext->Encrypt(publicKey, compVectPT);
            compVectTCs.push_back(compVectCT);
        }

        cout << "len compVectTCs = " << compVectTCs.size() << endl;
    }

    

    
    for (int subject = start; subject < end+1; subject++)
    {
        /////////////////////
        // Enrollment Phase
        ///////////////////// 

        string rawRefFile = SAMPLESDIR+to_string(subject)+"_1.txt";
        auto rawRef = readLineDouble(rawRefFile);
        auto quantizedRef = quantizeFeaturesBoddeti(precision, rawRef); 


        TIC(t);
        auto refTempCT = encryptVectorInt64(cryptoContext, keyPair, quantizedRef);
        toc = TOC_MS(t);
        writeProcTime(refTempGenRuntime, toc);
        cout << "Reference template is encrypted, it took "<< toc << "ms" << endl;




        /////////////////////
        // Verification Phase
        ///////////////////// 


        string rawProbeFile = SAMPLESDIR+to_string(subject)+"_2.txt";
        auto rawProbe = readLineDouble(rawProbeFile); 
        auto quantizedProb = quantizeFeaturesBoddeti(precision, rawProbe);  
        

        TIC(t);          
        auto probeTempCT = encryptVectorInt64(cryptoContext, keyPair, quantizedProb);
        toc = TOC_MS(t);
        writeProcTime(probTempGenRuntime, toc);
        cout << "Probe template is encrypted, it took "<< toc << "ms" << endl;

        if(subject == start)
        {
            saveInBinaryFile(referenceTempSTR, refTempCT);
            saveInBinaryFile(probeTempSTR, probeTempCT);
        }


        if (mode == "CleartextDecision")
        { 
            TIC(t);
            auto finalScoreCT = computeFinalScoreIPBoddeti(cryptoContext, refTempCT, probeTempCT, row_size);
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
            auto finalScoreCT1 = computeFinalScoreIPBoddeti(cryptoContext, refTempCT, probeTempCT, row_size);    

            // compute the blinded comparison vector (.., (S-theta_{i})*r_{i}, ...)_{i} 
            // where theta_{i} \in [T, Smax] and r_{i} is rand used for the blinding 
            size_t lenCom = compVectTCs.size();
            vector<Ciphertext<DCRTPoly>> decisionCT;
            for (size_t i = 0; i < lenCom; i++)               
            {
                auto finalScoreCT = cryptoContext->EvalAdd(finalScoreCT1, compVectTCs.at(i));
                auto ct = cryptoContext->EvalMult(finalScoreCT, blindRCT); 
                decisionCT.push_back(ct);
            }


            bool res = false;

            for (size_t i = 0; i < lenCom; i++)
            {
                Plaintext decisionPT;
                cryptoContext->Decrypt(secretKey, decisionCT.at(i), &decisionPT); 
                decisionPT->SetLength(row_size);
                res = verifyComparisonBinaryTree(decisionPT->GetPackedValue());
                if (res == true)
                {
                    break;
                }
                
            }  
            string verifyRes = (res)? "Match" : "No Match";
            toc = TOC_MS(t);
            writeProcTime(verificationRuntime, toc);
            cout << "Verification of subject " << subject << " is a " << verifyRes << endl;
            cout << "Verification took "<< toc << "ms" << endl;

        }
        
    }


    return 0;
}