# Improved Multiplication-Free Biometric Recognition for Faster Processing under Encryption

## Description

This repository contains a proof-of-concept implementation of an improved integration of MFIP with homomorphic encryption (HE) to perform biometric verification.


Assuming normalized feature vectors, the MFIP lookup table is parametrized by the feature vectors' dimension $d$, a feature quantization level $2^n$ where $n$ expresses the number of bits, and a cell quantization step $\Delta$, which we denote as MFIP$(d,n,\Delta)$.

## Remark

The use of the MFIP lookup tables is not restricted to biometric recognition.
They can be used in any other application involving the computation of the IP of two normalized vectors, not necessarily feature vectors.

## Dependencies 

This is a C++ implementation that requires the following libraries:

- [`OpenFHE version v1.0.4`](https://github.com/openfheorg/openfhe-development)
- [`OpenMP`](https://www.openmp.org/)


## Datasets

- Synthetic normalized feature vectors can be used
- Facial feature vectors of dimension 512 from [VGGFace2](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8373813) dataset to extract facial feature vectors of dimension 512 using [ResNet-100](https://openaccess.thecvf.com/content_cvpr_2016/papers/He_Deep_Residual_Learning_CVPR_2016_paper.pdf) trained by two different losses: one trained with [ArcFace](https://openaccess.thecvf.com/content_CVPR_2019/papers/Deng_ArcFace_Additive_Angular_Margin_Loss_for_Deep_Face_Recognition_CVPR_2019_paper.pdf) and another one trained with [CosFace](https://openaccess.thecvf.com/content_cvpr_2018/papers/Wang_CosFace_Large_Margin_CVPR_2018_paper.pdf).

## Experiments 

The following experiments consider the HE-based BTPs using OpenFHE BFVrns as an HE scheme: 
> * The MFIPv1 BTP, which is the initial integration of MFIP with HE as described in [[BHVP22]](https://ieeexplore.ieee.org/abstract/document/10007958).
> * The MFIPv2 BTP is an improved integration of MFIP with HE.
> * The HE-based baseline for the IP
> * Boddeti's BTP [[B18]](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8698601) that performs the IP over normalized vectors, which we re-implemented with OpenFHE.


Before launching the below experiments, execute the following commands

```
sudo mkdir build
cd build
sudo cmake ..
```


#### Experiments for measuring the runtime and storage

The file name of experiments measuring the runtime is `exp<BTP>Verification.cpp` where `BTP = {MFIPv1, MFIPv2, IPBaseline, IPBoddeti}` for the HE-based BTPs that can be run in two modes: the clear-text comparison with the threshold `MODE = 0` or the encrypted comparison with the threshold `MODE = 1` using [[BHP+21]](https://ieeexplore.ieee.org/abstract/document/9585508).

To run the above experiments, execute the following commands where `nBits = {128, 192, 256}` corresponds to the security levels.

```
cd build
sudo make exp<BTP>Verification
./exp<BTP>Verification <nBits> <firstSubjID> <lastSubjID> <MODE>
```






### Cleaning data

To clean up the generated data at once, execute the following
```
sudo make clean-data
```

## References

[[ B18 ]](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8698601)
[[BHP+21]](https://ieeexplore.ieee.org/abstract/document/9585508)
[[BHVP22]](https://ieeexplore.ieee.org/abstract/document/10007958)


## Bibtex Citation

```
This is an accepted paper at the IEEE T-BIOM Journal. The proper citation will be made available soon. 
```
