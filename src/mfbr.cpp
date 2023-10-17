#include "../include/mfbr.hpp"
#include <string>
#include <fstream>
#include <iomanip>
#include <algorithm>


using namespace lbcrypto;
using namespace std;

void printVectorInt64(vector<int64_t> vectInt){
	cout << "Contents of the vector: ";
    for(auto n: vectInt) cout << n << ' ';
    cout << '\n';
}


void writeProcTime(string filename, double processingTime){
    ofstream out_file;
    out_file.open(filename, ios::app);
    if (!out_file)
    {
        throw "Error creating file";
    }
    out_file << processingTime << endl;  
    out_file.close();
}

const vector<string> explode(const string& s, const char& c)
{
	string buff{ "" };
	vector<string> v;

	for (auto n : s)
	{
		if (n != c) buff += n; else
			if (n == c && buff != "") { v.push_back(buff); buff = ""; }
	}
	if (buff != "") v.push_back(buff);

	return v;
}

vector<int> genVectOfInt(int begin, size_t len){
	vector<int> vectInts(len);   
    iota(vectInts.begin(), vectInts.end(), begin);
	return vectInts;
}

vector<int> genVectOfPowOf2(size_t len){
	vector<int> vectPowOf2(len);   
	for (size_t i = 0; i < len; i++)
	{
		vectPowOf2.push_back(pow(2,i));
	}
	return vectPowOf2;
}

vector<double> readLineDouble(string filename){
	ifstream in_file; 
    string line;
    vector<string> strVect;
    vector<double> lineDouble;

    string str;
    in_file.open(filename);
    if (!in_file)
    {
        throw invalid_argument("file open error");
    }

	getline(in_file, line);
	strVect = explode(line, ',');
	for(auto s : strVect){
		lineDouble.push_back(stold(s)); 
	}  
    in_file.close();
    return lineDouble;
}


map< int, vector<int64_t>> readTableInt64(string filename, size_t nRows){
	ifstream in_file; 
    string line;
    vector<string> strVect;
    map<int, vector<int64_t>> table;
    string str;
    in_file.open(filename);
    if (!in_file)
    {
        throw invalid_argument("file open error");
    }
    
    for (size_t r = 0; r < nRows; r++){
        table[r].resize(0);
        getline(in_file, line);
        strVect = explode(line, ',');
        for(auto s : strVect){
            table[r].push_back(stoi(s)); 
        }
        strVect.resize(0);
    }    
    in_file.close();
    return table;
}

vector<int64_t> genVectOfInt64Neg(int64_t begin, size_t len){
	vector<int64_t> vectInts(len);	
	iota(vectInts.begin(), vectInts.end(), begin);   
	transform(vectInts.cbegin(),vectInts.cend(),vectInts.begin(), negate<int64_t>());
	return vectInts;
}

vector<int> vectIntPermutation(int seed, int begin, size_t len){
	vector<int> permuted;
	srand(seed + time(0));
	permuted = genVectOfInt(begin, len);
	shuffle(permuted.begin(), permuted.end(), default_random_engine(rand()));	
	return permuted;
}

map<int, vector<int>> genPermutations(int seed, size_t nPerm, size_t lenPerm){
	map<int, vector<int>> permutedMap;
	for(size_t i = 0; i<nPerm; i++){
		
		permutedMap[i] = vectIntPermutation( seed + i, 0, lenPerm);
	}
	return permutedMap;
}

vector<int64_t> vectIntPermutationInt64Neg(int seed, int64_t begin, size_t len){
	vector<int64_t> permuted = genVectOfInt64Neg(begin, len);
	srand(seed + time(0));	
	shuffle(permuted.begin(), permuted.end(), default_random_engine(rand()));	
	return permuted;
}

vector<int64_t> quantizeFeatures(vector<double> borders, vector<double> unQuantizedFeatures){
    auto numFeat = unQuantizedFeatures.size();
    vector<int64_t> quantizedFeatures;
    int count, len;
	double feature;
	len = borders.size();
	for (size_t i = 0; i < numFeat; i++)
	{

		feature = unQuantizedFeatures.at(i);
		count = 0;
		while( borders.at(count) <= feature){
			count++;
			if(count == len){
				break;
			}
		}
		quantizedFeatures.push_back(count);
	}
    return quantizedFeatures;
}

vector<int64_t> quantizeFeaturesBoddeti(int precision, vector<double> unQuantizedFeatures){	
	size_t nFeat = unQuantizedFeatures.size();
	vector<int64_t> quantizedFeatures(nFeat);
	#pragma omp parallel for schedule(dynamic,1)
	for (size_t i = 0; i < nFeat; i++)
	{
		quantizedFeatures.at(i) = (int64_t) roundf(precision*unQuantizedFeatures.at(i));
	}	
	return quantizedFeatures;
}

vector<int64_t> genRandVectOfInt64(int64_t begin, int64_t end, size_t len){
	random_device randDevice;
    unsigned seed = randDevice();    
    default_random_engine randEngine(seed);
	uniform_int_distribution<int64_t> unitDist(begin, end);
	vector<int64_t> randVect(len);
	for (size_t i = 0; i < len; i++)
	{		
		randVect.at(i) = unitDist(randEngine);
	}	
	return randVect;
}

// vector<double> genRandVectOfDouble(double begin, double end, size_t len){
// 	random_device randDevice;
//     unsigned seed = randDevice();    
//     default_random_engine randEngine(seed);
// 	uniform_int_distribution<double> unitDist(begin, end);
// 	vector<double> randVect(len);
// 	for (size_t i = 0; i < len; i++)
// 	{		
// 		randVect.at(i) = unitDist(randEngine);
// 	}	
// 	return randVect;
// }

Ciphertext<DCRTPoly> encryptVectorInt64(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, vector<int64_t> vect){  	
	auto vectEnc = cryptoContext->MakePackedPlaintext(vect);
	auto vectEncCT = cryptoContext->Encrypt(keyPair.publicKey, vectEnc);
	return vectEncCT;
}

vector<vector<int64_t>> packRefTemplate2(vector<int64_t> sampleQ, map<int, vector<int64_t>> mfbrTab, size_t nPackedRowsPerCipher, size_t numCiphers){
	vector<vector<int64_t>> refTempPacked(numCiphers);
	#pragma omp parallel for schedule(dynamic)
	for (size_t i = 0; i < numCiphers; i++) {		
		vector<int64_t> packedRows;
		for (size_t j = i * nPackedRowsPerCipher; j < (i+1) * nPackedRowsPerCipher; j++)
		{
			auto refTemp = mfbrTab[sampleQ.at(j)];
			packedRows.insert(packedRows.end(), refTemp.begin(), refTemp.end());
		}
		refTempPacked.at(i) = packedRows;
	}
	return refTempPacked;
}

vector<int64_t> refTemplate(vector<int64_t> sampleQ, map<int, vector<int64_t>> mfbrTab){
	vector<int64_t> refTempPacked;
	for (auto &&i : sampleQ)
	{
		auto refTemp = mfbrTab[i];
		refTempPacked.insert(refTempPacked.end(), refTemp.begin(), refTemp.end());
	}
	return refTempPacked;
}

vector<int> genPackedProbeIndexes(vector<int64_t> probSampleQ, map<int, vector<int>> permutations, size_t nPackedRowsPerCipher, size_t nRows){	
	
	size_t nFeat = probSampleQ.size();
	vector<int> permProbInd(nFeat);
	#pragma omp parallel for schedule(dynamic)
	for (size_t i = 0; i < nFeat; i++)
	{	
		size_t colInd = (size_t) ((i % nPackedRowsPerCipher) * nRows + (int) probSampleQ.at(i));
		size_t rowInd = (size_t) (i / nPackedRowsPerCipher);
		permProbInd.at(i) = permutations[rowInd].at(colInd);
		
	}
	return permProbInd;

}

vector<int64_t> permuteSample(vector<int64_t> sample, vector<int> permutation){
	auto len = permutation.size();
	vector<int64_t> permuted(len);
	#pragma omp parallel for schedule(dynamic,1)
	for (size_t i = 0; i < len; i++)
	{
		permuted.at(permutation.at(i)) = sample.at(i);
	}
	return permuted;
}

vector<Ciphertext<DCRTPoly>> genEncryptedReferenceTemplate(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair, vector<vector<int64_t>> reftemp, map<int, vector<int>> permutations){    
    auto nCiphers = reftemp.size();
	vector<Ciphertext<DCRTPoly>> encRefTempCT(nCiphers);
	#pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < nCiphers; i++)
    {
		auto permutedReftemp = permuteSample(reftemp.at(i), permutations[i]);
		auto permReftemp = cryptoContext->MakePackedPlaintext(permutedReftemp);
        encRefTempCT.at(i) = cryptoContext->Encrypt(keyPair.publicKey, permReftemp);
    }
	return encRefTempCT;
}

Ciphertext<DCRTPoly> computeFinalScoreIPBaseline(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> encRefTempCT, Ciphertext<DCRTPoly> encProbeCT, Ciphertext<DCRTPoly> oneAndZerosCT, size_t nFeat){
	auto probeRefTempIP = cryptoContext->EvalMult(encRefTempCT, encProbeCT);
	Ciphertext<DCRTPoly> fsc = cryptoContext->EvalRotate(probeRefTempIP, 0);
    for (size_t i = 1; i < nFeat; i++)
    {
		auto rotCT = cryptoContext->EvalRotate(probeRefTempIP, i); 
		fsc = cryptoContext->EvalAdd(fsc, rotCT);
    }
    auto finalScoreCT = cryptoContext->EvalMult(fsc, oneAndZerosCT);
	return finalScoreCT;
}

Ciphertext<DCRTPoly> computeFinalScoreSEDBaseline(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> encRefTempCT, Ciphertext<DCRTPoly> encProbeCT, Ciphertext<DCRTPoly> oneAndZerosCT, size_t nFeat){
	auto refTempMinusProbe = cryptoContext->EvalSub(encRefTempCT, encProbeCT);
	auto probeRefTempSED = cryptoContext->EvalMult(refTempMinusProbe, refTempMinusProbe);
	Ciphertext<DCRTPoly> fsc = cryptoContext->EvalRotate(probeRefTempSED, 0);
    for (size_t i = 1; i < nFeat; i++)
    {
		auto rotCT = cryptoContext->EvalRotate(probeRefTempSED, i); 
		fsc = cryptoContext->EvalAdd(fsc, rotCT);
    }
	auto finalScoreCT = cryptoContext->EvalMult(fsc, oneAndZerosCT);
	return finalScoreCT;
}

vector<vector<int>> getIndexRotationGroups(vector<int> permProbInd){
	vector<vector<int>> rotationIndexes(8);
	int nFeat = permProbInd.size();
	for (int i = 0; i < nFeat; i++)
	{
		rotationIndexes.at(permProbInd.at(i)).push_back(i);
	}
	
	return rotationIndexes;
}

Ciphertext<DCRTPoly> getRotationGroupAtIndex(CryptoContext<DCRTPoly> cryptoContext, vector<Ciphertext<DCRTPoly>> encRefTempCT, vector<int> rotaionIndexesInd, int ind){
	int nC = rotaionIndexesInd.size();
	vector<Ciphertext<DCRTPoly>> rotationGroup(nC);	
	#pragma omp parallel for schedule(static,1)	
	for (int i = 0; i < nC; i++)
	{
		rotationGroup.at(i) = encRefTempCT.at(rotaionIndexesInd.at(i));				
	}
	auto ct = cryptoContext->EvalAddMany(rotationGroup);
	if (ind == 0)
	{
		return ct;
	}
	return cryptoContext->EvalRotate(ct, ind);
}

Ciphertext<DCRTPoly> computeFinalScoreMFBRClearComp(CryptoContext<DCRTPoly> cryptoContext, vector<Ciphertext<DCRTPoly>> encRefTempCT, vector<int> permProbInd, Ciphertext<DCRTPoly> blindRCT, size_t nPackedRowsPerCipher, int nRows){
	auto rotaionIndexes = getIndexRotationGroups(permProbInd);
	vector<Ciphertext<DCRTPoly>> selectIndScores(nRows+1);
	#pragma omp parallel for schedule(static,1)
	for (int i = 0; i < nRows; i++)
	{
		selectIndScores.at(i) = getRotationGroupAtIndex(cryptoContext, encRefTempCT, rotaionIndexes.at(i), i);
	}
	selectIndScores.at(nRows) = blindRCT;
	return cryptoContext->EvalAddManyInPlace(selectIndScores);
}

Ciphertext<DCRTPoly> computeFinalScoreForBlindedCompGroups(CryptoContext<DCRTPoly> cryptoContext, vector<Ciphertext<DCRTPoly>> encRefTempCT, vector<int> permProbInd, Plaintext onePlain){
	auto rotaionIndexes = getIndexRotationGroups(permProbInd);
	vector<Ciphertext<DCRTPoly>> selectIndScores(8);
	#pragma omp parallel for schedule(static,1)
	for (int i = 0; i < 8; i++)
	{
		selectIndScores.at(i) = getRotationGroupAtIndex(cryptoContext, encRefTempCT, rotaionIndexes.at(i), i);
	}
	auto finalScoreCT = cryptoContext->EvalAddManyInPlace(selectIndScores);
	return cryptoContext->EvalMult(finalScoreCT, onePlain);      
}

/* The function computeFinalScoreIPBoddeti implements Algorithm 1 and Figure 3 in [B18] in PALISADE.

[B18] Boddeti, V. N. (2018, October). Secure face matching using fully homomorphic encryption. In 2018 IEEE 9th International Conference on Biometrics Theory, Applications and Systems (BTAS) (pp. 1-10). IEEE.
*/

Ciphertext<DCRTPoly> computeFinalScoreIPBoddeti(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> encRefTempCT, Ciphertext<DCRTPoly> encProbeCT, size_t row_size){
	auto probeRefTempIP = cryptoContext->EvalMult(encRefTempCT, encProbeCT);
	Ciphertext<DCRTPoly> finalScoreCT = probeRefTempIP;
    for (size_t i = 0; i < log2(row_size); i++)
    {
		probeRefTempIP = cryptoContext->EvalRotate(finalScoreCT, pow(2,i)); 
		cryptoContext->EvalAddInPlace(finalScoreCT, probeRefTempIP);
    }
	
	return finalScoreCT;
}

bool verifyComparisonInt64(vector<int64_t> blindedCompVect){
	for (size_t i = 0; i < blindedCompVect.size(); i++)
	{
		if (blindedCompVect.at(i) == 0)
		{
			return true;
		}
	}
	
	return false;
}

bool verifyComparisonBinaryTree(vector<int64_t> blindedCompVect){
	int64_t zero(0);
	sort(blindedCompVect.begin(), blindedCompVect.end());
	return binary_search(blindedCompVect.begin(), blindedCompVect.end(), zero);
}

bool verifyComparison(Plaintext blindedCompVectPlain, size_t len){
	blindedCompVectPlain->SetLength(len);
	auto blindedValues = blindedCompVectPlain->GetPackedValue();
	// blindedValues.resize(len);

	auto res = accumulate(begin(blindedValues), end(blindedValues), 1, std::multiplies<int64_t>());
	if (res == 0)
	{
		return true;
	}
	return false;
}



/*
	MFIP version 2.0
*/ 

Ciphertext<DCRTPoly> encryptPermutedRefTempSingleCT(PublicKey<DCRTPoly> publicKey, vector<int64_t> refTemp, vector<int> permutations){
	auto cryptoContext = publicKey->GetCryptoContext();
    auto ringDim = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2;
    auto nTemp = refTemp.size();
	vector<int64_t> permRefTemp(ringDim);
    
    #pragma omp parallel for schedule(static,2)
    for (size_t i = 0; i < nTemp; i++)
    {
        permRefTemp[i] = refTemp[permutations[i]];
    }

	auto permRefTempPT = cryptoContext->MakePackedPlaintext(permRefTemp);

	Ciphertext<DCRTPoly> permRefTempCT = cryptoContext->Encrypt(publicKey, permRefTempPT); 

    return permRefTempCT;
}

vector<int64_t> getPermutedProbeTempMask(vector<int>& permProbeTemp, size_t ringDim){
	size_t nFeat = permProbeTemp.size();
	vector<int64_t> permProbeTempMask(ringDim,0);
	#pragma omp parallel for schedule(static,2)
    for (size_t i = 0; i < nFeat; i++)
    { 
        permProbeTempMask[permProbeTemp[i]] = 1;
    }

	return permProbeTempMask;
}

Ciphertext<DCRTPoly> getFinalScoreCT(const Ciphertext<DCRTPoly> permRefTempCT, vector<int64_t> permProbeTempMask){
	auto cryptoContext = permRefTempCT->GetCryptoContext();
	size_t ringDim = cryptoContext->GetRingDimension();
	size_t halfRing = (size_t) ringDim/2;

	auto permProbeTempMaskPT = cryptoContext->MakePackedPlaintext(permProbeTempMask);
	auto maskedRefTempCT = cryptoContext->EvalMult(permRefTempCT, permProbeTempMaskPT);	
	
	Ciphertext<DCRTPoly> finalScoreCT = maskedRefTempCT;
    for (size_t i = 0; i < log2(halfRing); i++)
    {
		maskedRefTempCT = cryptoContext->EvalRotate(finalScoreCT, pow(2,i)); 
		cryptoContext->EvalAddInPlace(finalScoreCT, maskedRefTempCT);
    }
	
	return finalScoreCT;
}


vector<int64_t> revealFinalScores(PrivateKey<DCRTPoly> secretKey, Ciphertext<DCRTPoly>  ct){
    Plaintext pt;
    auto cryptoContext = ct->GetCryptoContext();
    cryptoContext->Decrypt(secretKey, ct, &pt);
    return pt->GetPackedValue();
}


vector<int> getPermutationsInverse(vector<int> permutations){
    int nLen = permutations.size();
    vector<int> permutationsInverse(nLen);
    #pragma omp parallel for schedule(static,2)
    for (int i = 0; i < nLen; i++)
    { 
        permutationsInverse.at(i) = getIndexInVect(permutations, i);
    }
    return permutationsInverse;
}

vector<int> genPermProbeTemplateFromPermInv(vector<int64_t> quantizedProb, vector<int> permutationsInverse, size_t lenRow){
    auto dim = quantizedProb.size();
    vector<int> permProbeTemp(dim);
    #pragma omp parallel for schedule(static,2)
    for (size_t i = 0; i < dim; i++)
    { 
        int val = (int) quantizedProb.at(i) + (int) i*lenRow;
        permProbeTemp.at(i) = permutationsInverse[val];

    }
    return permProbeTemp;
}

/* concatenate the permutations and adapt them to concatenated indexes*/
vector<int> genPermutationsConcat(int seed, size_t nPerm, size_t lenPerm){
	vector<int> permutations;
	for(size_t i = 0; i<nPerm; i++){		
		auto perm = vectIntPermutation( seed + i, 0, lenPerm);
        perm = addSameValToVector(perm , i*lenPerm);
        permutations.insert(permutations.end(), perm.begin(), perm.end());
	}    
	return permutations;
}

vector<int> addSameValToVector(vector<int> vect, int val){
    transform(vect.begin(), vect.end(), vect.begin(),
               [=](int i) { return i + val; });
    return vect;
}