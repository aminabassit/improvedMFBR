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


const string FBORDERS = "../lookupTables/Borders_nB_3_dimF_512.txt";
const string SAMPLESDIR = "../data/VGGFace2/ArcFace-R100/ArcFace-R100_";
const size_t NROWS = 8;
const int NFEAT = 512;
const size_t COMPLEN = 4146;
const int64_t THRESHOLD = 5498;
const int SEED = 45676;

int main(int argc, char *argv[]) {
    
    double toc;
    TimeVar t;
    string sBits = argv[1]; 
    int multDepth(2); 
    int start = stoi(argv[2]);
    int end = stoi(argv[3]);






    string mode;  
    if (stoi(argv[4]) == 0)
    {
        mode = "CleartextDecision";
    }
    else if (stoi(argv[4]) == 1)
    {
        mode = "EncryptedDecision";
    }
    else
    {
        cout << "Choose one of the following search modes: 0: Cleartext Decision or 1: Encrypted Decision" << endl;
    }    



    string mainDir("../results/experimentsBaselineIP-BFVrns/BaselineIP-"+mode);
    createNestedDirs(mainDir);

    string referenceTempSTR = mainDir+"/reference-BaselineIP-"+sBits+".txt";
    string probeTempSTR = mainDir+"/probe-BaselineIP-"+sBits+".txt";

    string enrollRuntime = mainDir+"/expBaselineIP-Enrollment-"+sBits+".csv";
    string verificationRuntime = mainDir+"/expBaselineIP-Verification-"+sBits+".csv";

    string refTempGenRuntime = mainDir+"/expBaselineIP-permRefTempGen-"+sBits+".csv";
    string probTempGenRuntime = mainDir+"/expBaselineIP-probTempGen-"+sBits+".csv";



    cout << "Security "+sBits+" bits" << endl;



    

    int64_t nBits(20);  
    uint64_t m(32768);
    auto plaintextMod = FirstPrime<NativeInteger>(nBits, m);
    usint plaintextModulus = (usint) plaintextMod.ConvertToInt();


    

    CCParams<CryptoContextBFVRNS> parameters;
    SecurityLevel securityLevel;  
    double statisticalSecurity;  
    usint multiplicativeDepth(multDepth); 
    size_t dcrtBits(0);
    

    if (sBits == "128")
    {
        securityLevel = HEStd_128_classic;
        statisticalSecurity = 128/2;
        dcrtBits = (stoi(argv[4]) == 0)? 36 : 37;
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

    // Loading borders
    auto borders = readLineDouble(FBORDERS);

    // Generate the rotation evaluation keys

    auto shiftIndexes = genVectOfInt(0, NFEAT+1);
    for (int i = 0; i < log2(row_size)+1; i++)
    {
        shiftIndexes.push_back(pow(2,i));   
    } 
    cryptoContext->EvalRotateKeyGen(secretKey, shiftIndexes);


    cout << "Keys successfully generated ..." << endl; 

    
    Plaintext compVectPT, blindRPT; 
    Ciphertext<DCRTPoly> blindRCT;
    vector<Ciphertext<DCRTPoly>> compVectTCs;
    

    if (stoi(argv[4]) == 1)
    {
    
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
        auto quantizedRef = quantizeFeatures(borders, rawRef); 


        TIC(t);
        auto refTempCT = encryptVectorInt64(cryptoContext, keyPair, quantizedRef);
        toc = TOC_MS(t);
        writeProcTime(refTempGenRuntime, toc);
        cout << "Reference template is encrypted, it took "<< toc << "ms" << endl;


        // For isolating the first plaintext slot 
        vector<int64_t> vectOneAndZeros(ringDim, 0); 
        vectOneAndZeros.at(0) = 1;
        auto oneAndZerosPT = cryptoContext->MakePackedPlaintext(vectOneAndZeros);
        auto oneAndZerosCT = cryptoContext->Encrypt(publicKey, oneAndZerosPT);



        /////////////////////
        // Verification Phase
        /////////////////////  

        string rawProbeFile = SAMPLESDIR+to_string(subject)+"_2.txt";
        auto rawProbe = readLineDouble(rawProbeFile); 
        auto quantizedProb = quantizeFeatures(borders, rawProbe);  
        

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
            auto finalScoreCT = computeFinalScoreIPBaseline(cryptoContext, refTempCT, probeTempCT, oneAndZerosCT, NFEAT); 
            Plaintext finalScorePT;
            cryptoContext->Decrypt(secretKey, finalScoreCT, &finalScorePT);
            auto fs = finalScorePT->GetPackedValue().at(0);
            string verifyRes = (fs<THRESHOLD)? "No Match" : "Match";            
            toc = TOC_MS(t);
            writeProcTime(verificationRuntime, toc);
            cout << "Verification of subject " << subject << " is a " << verifyRes << endl;
            cout << "Verification took "<< toc << "ms" << endl;
        }
        if (mode == "EncryptedDecision")
        {
            TIC(t); 
            auto finalScoreCt0 = computeFinalScoreIPBaseline(cryptoContext, refTempCT, probeTempCT, oneAndZerosCT, NFEAT); 
            

            // replicate the final score 'S' over all plaintext slots to get (S, S, ..., S)
            Ciphertext<DCRTPoly> finalScoreCT1 = finalScoreCt0;       
            for (size_t i = 0; i < log2(row_size); i++)
            {
                finalScoreCt0 = cryptoContext->EvalRotate(finalScoreCT1, pow(2,i)); 
                cryptoContext->EvalAddInPlace(finalScoreCT1, finalScoreCt0);
            }             

            // compute the blinded comparison vector (.., (S-theta_{i})*r_{i}, ...)_{i} 
            // where theta_{i} \in [T, Smax] and r_{i} is rand used for the blinding 
            size_t lenCom = compVectTCs.size();
            vector<Ciphertext<DCRTPoly>> decisionCT;
            for (size_t i = 0; i < lenCom; i++)               
            {
                auto finalScoreCT = cryptoContext->EvalAdd(finalScoreCT1, compVectTCs.at(i));
                auto ct = cryptoContext->EvalMult(finalScoreCT, blindRPT); 
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