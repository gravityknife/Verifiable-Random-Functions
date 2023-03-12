# Verifiable-Random-Functions

We implemented RSA VRF on Python2 fulfilling the properties of trusted uniqueness, trusted collision resistance, and full pseudorandomness.

USAGE: python RSA_VRF.py [alpha]

This code takes alpha and generates a proof and then proceeds to verify it. You can modify the size of the proof by modifying the variable k. 
The slides are in the LaTeX PDF and make sure to install the libraries in the requirements.txt.

Implemented psudo code from https://www.ietf.org/archive/id/draft-vcelak-nsec5-08.txt
