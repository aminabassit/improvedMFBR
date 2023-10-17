#pragma once
#include <iostream>
#include <sys/stat.h>

#include <openfhe.h>
#include <openfhecore.h>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"


using namespace std;
using namespace lbcrypto;

template <class T>
void saveInBinaryFile(string itemFile, T item){
    if (!Serial::SerializeToFile(itemFile, item, SerType::BINARY)) {
    std::cerr  << "Error writing serialization of "+ itemFile  << std::endl;
    } 
}


vector<string> split(const string &str, char delimiter);
void createDir(string directoryPath);
void createNestedDirs(string nestedDirsPath);

