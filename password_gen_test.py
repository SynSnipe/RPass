#!/usr/bin/env python3

import random
import sys
import argparse

def buildCharSet(inputList):
    charlist = []
    # lowercase letters
    if inputList[0]:
        for lletter in "abcdefghijklmnopqrstuvwxyz":
            charlist.append(lletter)
    # uppercase letters
    if inputList[1]:
        for uletter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            charlist.append(uletter)
    # numbers
    if inputList[2]:
        for number in "0123456789":
            charlist.append(number)
    # special characters
    if inputList[3]:
        for specchar in "!@#$%^&*,./":
            charlist.append(specchar)

    return charlist


def password(length=12, charlist=[]):
    password = []
    for x in range(0, length):
        charnum = random.randint(0, len(charlist) - 1)
        password.append(charlist[charnum])
    print("Random Password: %s" % "".join(password))


def main():
    parser = argparse.ArgumentParser(description='Random Password Generation Testing Script')
    parser.add_argument('-c', '--count', help="Count of characters in password", default=12)
    parser.add_argument('-l', '--lower', action="store_true", help="Use Lower Case Letters")
    parser.add_argument('-u', '--upper', action="store_true", help="Use Upper Case Letters")
    parser.add_argument('-n', '--num', action="store_true", help="Use Numbers")
    parser.add_argument('-s', '--special', action="store_true", help="Use Special Characters !@#$%^&*,./")

    global args
    args = parser.parse_args()

    if args.lower or args.upper or args.num or args.special:
        myCharacterList = buildCharSet([args.lower, args.upper, args.num, args.special])
        password(length=int(args.count), charlist=myCharacterList)
    else:
        print("You have to specify at least one character type!!!")
        sys.exit(1)


if __name__ == "__main__":
    main()