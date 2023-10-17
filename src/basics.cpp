#include <iostream>
#include <sys/stat.h>
#include <sstream>
#include <vector>
#include <algorithm>

#include "../include/basics.hpp"



using namespace std;



vector<string> split(const string &str, char delimiter) {
  vector<string> tokens;
  stringstream ss(str);
  string token;
  while (getline(ss, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}

void createDir(string directoryPath){
    struct stat info;
    if (stat(directoryPath.c_str(), &info) != 0) {
        int status = mkdir(directoryPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (status == -1) {
        cerr << "Error creating directory: " << directoryPath << endl;
        }
    } else if (info.st_mode & S_IFDIR) {
    } else {
        cerr << "Error: " << directoryPath << " is not a directory" << endl;
    }
}

void createNestedDirs(string nestedDirsPath){
    auto dirSplitted = split(nestedDirsPath, '/');
    string mainDir = dirSplitted[0];    
    for (size_t i = 1; i < dirSplitted.size(); i++)
    {
        mainDir += '/'+dirSplitted[i];
        createDir(mainDir);
    }
}

