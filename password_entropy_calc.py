#!/usr/bin/env python3

import random
import sys
import argparse
import math


def hasNumber(inputStr):
    return any(char.isdigit() for char in inputStr)


def hasLower(inputStr):
    return any(char.islower() for char in inputStr)


def hasUpper(inputStr):
    return any(char.isupper() for char in inputStr)


def hasSpec(inputStr):
    return any(char in "!@#$%^&*,./~`'\"[]{}()=+\\|;:<>-_?" for char in inputStr)


def entropyCalc(password):

    formula = """E = log2(R^L)
        where:
            E = password entropy
            R = pool of unique characters
            L = number of characters in your password
            R^L = the number of possible passwords
            log2(R^L) = the number of bits of entropy
    """
    poolOfChars = 0
    if hasLower(password):
        poolOfChars += 26
    if hasUpper(password):
        poolOfChars += 26
    if hasNumber(password):
        poolOfChars += 10
    if hasSpec(password):
        poolOfChars += 32
    rToL = pow(poolOfChars, len(password))
    entropy = math.log2(rToL)
    return entropy


def main():
    parser = argparse.ArgumentParser(description='Password Entropy Calculator')
    global args
    args = parser.parse_args()
    password = ""

    while password == "":
        password = input("\n\tInput Password for Entropy Calculation: ")

    print("\nPassword: %s\t\t\tPassword Entropy: %.2f" % (password, entropyCalc(password)))


if __name__ == "__main__":
    main()