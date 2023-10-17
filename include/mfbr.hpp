#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <cmath>
#include <algorithm>
#include <cstdlib>
#include <random>
#include <iomanip>
#include <list>
#include <numeric>





#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

template<class T>
vector<T> genVectorOfNumbers(T begin, size_t len){
	vector<T> vect(len);   
    iota(vect.begin(), vect.end(), begin);
	return vect;
}

template <class T>
void printVector (T vect) {
    cout << "Contents of the vector: ";
    for(auto n: vect) cout << n << ' ';
    cout << '\n';
}

template <class T>
vector<int> findIndexes(vector<T> v, T key){
    vector<int> indexes;
    auto itr = find(v.begin(), v.end(), key);
    if (itr == v.cend())
    {
        return {-1};
    }
    else
    {
        auto a = distance(v.begin(), itr);
        while (itr != v.cend())
        {
            
            indexes.push_back(a);
            a+=1; 
            itr = find(v.begin()+a, v.end(), key);
            if (itr != v.cend())
            {
                a += distance(v.begin()+a, itr);
            }       

        }
    }    
    return indexes;
}

void printVectorInt64(vector<int64_t> vectInt);
void writeProcTime(string filename, double processingTime);
const vector<string> explode(const string& s, const char& c);
vector<int> genVectOfInt(int begin, size_t len);
vector<int> genVectOfPowOf2(size_t len);
vector<double> readLineDouble(string filename);
map< int, vector<int64_t>> readTableInt64(string filename, size_t nRows);
vector<int64_t> permuteSample(vector<int64_t> sample, vector<int> permutation);
map<int, vector<int>> genPermutations(int seed, size_t nPerm, size_t lenPerm);
vector<int64_t> vectIntPermutationInt64Neg(int seed, int64_t begin, size_t len);
vector<int64_t> genVectOfInt64Neg(int64_t begin, size_t len);
vector<int> vectIntPermutation(int seed, int begin, size_t len);
vector<vector<int>> getIndexRotationGroups(vector<int> permProbInd);


// vector<double> genRandVectOfDouble(double begin, double end, size_t len);

vector<int64_t> quantizeFeatures(vector<double> borders, vector<double> unQuantizedFeatures);
vector<int64_t> quantizeFeaturesBoddeti(int precision, vector<double> unQuantizedFeatures);


Ciphertext<DCRTPoly> getRotationGroupAtIndex(CryptoContext<DCRTPoly> cryptoContext, vector<Ciphertext<DCRTPoly>> encRefTempCT, vector<int> rotaionIndexesInd, int ind);
Ciphertext<DCRTPoly> encryptVectorInt64(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, vector<int64_t> vect);


vector<int64_t> genRandVectOfInt64(int64_t begin, int64_t end, size_t len);
vector<vector<int64_t>> packRefTemplate2(vector<int64_t> sampleQ, map<int, vector<int64_t>> mfbrTab, size_t nPackedRowsPerCipher, size_t numCiphers);
vector<int> genPackedProbeIndexes(vector<int64_t> probSampleQ, map<int, vector<int>> permutations, size_t nPackedRowsPerCipher, size_t nRows);
vector<Ciphertext<DCRTPoly>> genEncryptedReferenceTemplate(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, vector<vector<int64_t>> reftemp, map<int, vector<int>> permutations);



Ciphertext<DCRTPoly> computeFinalScoreIPBaseline(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> encRefTempCT, Ciphertext<DCRTPoly> encProbeCT, Ciphertext<DCRTPoly> oneAndZerosCT, size_t nFeat);
Ciphertext<DCRTPoly> computeFinalScoreSEDBaseline(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> encRefTempCT, Ciphertext<DCRTPoly> encProbeCT, Ciphertext<DCRTPoly> oneAndZerosCT, size_t nFeat);

Ciphertext<DCRTPoly> computeFinalScoreMFBRClearComp(CryptoContext<DCRTPoly> cryptoContext, vector<Ciphertext<DCRTPoly>> encRefTempCT, vector<int> permProbInd, Ciphertext<DCRTPoly> blindRCT, size_t nPackedRowsPerCipher, int nRows);
Ciphertext<DCRTPoly> computeFinalScoreForBlindedCompGroups(CryptoContext<DCRTPoly> cryptoContext, vector<Ciphertext<DCRTPoly>> encRefTempCT, vector<int> permProbInd, Plaintext onePlain);

Ciphertext<DCRTPoly> computeFinalScoreIPBoddeti(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> encRefTempCT, Ciphertext<DCRTPoly> encProbeCT, size_t row_size);






bool verifyComparisonInt64(vector<int64_t> blindedCompVect);
bool verifyComparison(Plaintext blindedCompVectPlain, size_t len);



// Identification 

vector<int64_t> refTemplate(vector<int64_t> sampleQ, map<int, vector<int64_t>> mfbrTab);



/*
	MFIP version 2.0
*/ 

Ciphertext<DCRTPoly> encryptPermutedRefTempSingleCT(PublicKey<DCRTPoly> publicKey, vector<int64_t> refTemp, vector<int> permutations);
vector<int64_t> getPermutedProbeTempMask(vector<int>& permProbeTemp, size_t ringDim);
Ciphertext<DCRTPoly> getFinalScoreCT(const Ciphertext<DCRTPoly> permRefTempCT, vector<int64_t> permProbeTempMask);
bool verifyComparisonBinaryTree(vector<int64_t> blindedCompVect);


vector<int64_t> revealFinalScores(PrivateKey<DCRTPoly> secretKey, Ciphertext<DCRTPoly>  ct);


vector<int> getPermutationsInverse(vector<int> permutations);
vector<int> genPermProbeTemplateFromPermInv(vector<int64_t> quantizedProb, vector<int> permutationsInverse, size_t lenRow);
vector<int> genPermutationsConcat(int seed, size_t nPerm, size_t lenPerm);


template <class T>
T getIndexInVect(const vector<T>& vect, T val){
    auto it = find(vect.begin(), vect.end(), val);
    if (it != vect.end())
    {
        return distance(vect.begin(), it);
    }
    return -1;
}

vector<int> addSameValToVector(vector<int> vect, int val);