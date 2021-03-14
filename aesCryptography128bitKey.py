# hex string to char print(bytes.fromhex("6312" or '63').decode('utf-8'))
# char to hex format(ord("abc" or 'abc'), "x") or string.hex().upper()
# hex to int int("hex",16) "a0" =>160 that is the index of array Sbox
# hex string to char print(bytes.fromhex("6312" or '63').decode('utf-8'))
# char to hex format(ord("abc" or 'abc'), "x")
# hex to int int("hex",16) "a0" =>160 that is the index of array Sbox
# hex to binary "1a" to 8bit binary  ("{0:08b}".format(int(hex_string, 16)))
# binary to hex (hex(int(binstr, 2))[2:] retrun 2 digit or 1 digit if first one is 0 or a hex array
# int to str => int(str)
# str to int => str(int)
#byte to hex str.hex()
#hex to byte bytes.fromhex("str")

from BitVector import *
import time
Sbox = [
    "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
    "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
    "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
    "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
    "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
    "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
    "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
    "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
    "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
    "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
    "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
    "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
    "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
    "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
    "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
    "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
]

InvSbox = [
    "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB",
    "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB",
    "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E",
    "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25",
    "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92",
    "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84",
    "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06",
    "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B",
    "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73",
    "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E",
    "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B",
    "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4",
    "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F",
    "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF",
    "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61",
    "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D",
]
AES_modulus = BitVector(bitstring='100011011')

#ascii string to hexstring
def charToHexString(s):
    hexString = ""
    for x in range(len(s)):
        hexString += format(ord(s[x]), "x")
    return hexString.upper()

#hex array to char array
def hexArrayToCharOneString(cypher):
    cypher =  [cypher[i:i + 2] for i in range(0, len(cypher), 2)]
    cypherInAscii=""
    for i in cypher:
            try:
                cypherInAscii += bytes.fromhex(i).decode("utf-8")
            except:
                cypherInAscii += ("\"" + i + "\"")
    return cypherInAscii

# generate g function takes array of hex as input
def circularLeftShift(hexArray, count=1):
    count = count % len(hexArray)
    for j in range(count):
        firstItem = hexArray[0]
        for i in range(len(hexArray)-1):
            hexArray[i] = hexArray[i+1]
        hexArray[len(hexArray)-1] = firstItem
    return hexArray

def circularRightShift(hexArray,count):
    count = count % len(hexArray)
    for j in range(count):
        lastItem = hexArray[len(hexArray)-1]
        for i in range(len(hexArray) - 1,0,-1):
            hexArray[i] = hexArray[i - 1]
        hexArray[0] = lastItem
    return hexArray

# will take an array of hex and substitute with Sbox
def substituteByteWithSbox(hexArray):
    for i in range(len(hexArray)):
        hexString = hexArray[i]
        intIndex = int(hexString, 16)
        replacedHex = Sbox[intIndex]
        hexArray[i] = replacedHex
    return hexArray

#will take an array of hex and substtue with inverseSbox
def substituteByteWithInverseSbox(hexArray):
    for i in range(len(hexArray)):
        hexString = hexArray[i]
        intIndex = int(hexString, 16)
        replacedHex = InvSbox[intIndex]
        hexArray[i] = replacedHex
    return hexArray

# input binary return xor
def binaryXOR(roundB, wordB):
    roundB = "0" * (8 - len(roundB)) + roundB
    wordB = "0" * (8 - len(wordB)) + wordB
    xorStr = ""
    for i in range(8):
        xorStr+=str(int(roundB[i])^int(wordB[i]))

    return xorStr


# add means xor round key with word
def addRoundKey(hexArray, roundKey):
    return xorArrayOfHexStrings(hexArray, roundKey)

#input two hex return one hex of xor
def xorTwoHex(hex1,hex2):
    hex1B = "{0:08b}".format(int(hex1, 16))
    hex2B = "{0:08b}".format(int(hex2, 16))
    xorB = binaryXOR(hex1B, hex2B)
    xorHex = hex(int(xorB, 2))[2:]
    if len(xorHex) != 2:
        xorHex = "0" + xorHex
    return xorHex


# input two word array return xor array of them
def xorArrayOfHexStrings(array1, array2):
    xordArray = []
    for i in range(len(array1)):
        xorHex = xorTwoHex(array1[i],array2[i])
        xordArray.append(xorHex)

    return xordArray


#split hex string into list of list
def splitHexString(hexString):
    hexStringArray = [hexString[i:i + 2] for i in range(0, len(hexString), 2)]
    index = 0
    hexStringListOfList = []
    for x in range(4):
        items = []
        for y in range(4):
            items.append(hexStringArray[index])
            index += 1
        hexStringListOfList.append(items)
    return hexStringListOfList


#generate round keys
def generateRoundKeys():
    # generate round key
    roundKey = ["01"]
    AES_modulus = BitVector(bitstring='100011011')
    for i in range(9):
        bv1 = BitVector(hexstring=roundKey[i])
        bv2 = BitVector(hexstring="02")
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        bv3str = str(bv3)
        bv3hex = hex(int(bv3str, 2))[2:]
        if len(bv3hex) < 2:
            bv3hex = "0" + bv3hex
        roundKey.append(bv3hex)
    return roundKey

#generate 44 keywords
def generateKeyWords(key,keylength,roundkeys):
    if len(key) > keyLength:
        key = key[:keyLength]
    elif len(key) < keyLength:
        key += "0" * (keyLength - len(key))

    w = []
    index = 0
    for x in range(4):
        items = []
        for y in range(4):
            items.append(format(ord(key[index]), "x"))
            index += 1
        w.append(items)

    w.append([])
    # circular left shitf
    w[4] = (circularLeftShift(w[3].copy(), 1))
    # Substitute with Sbox
    w[4] = substituteByteWithSbox(w[4])

    # add round key
    w[4] = addRoundKey(w[4], [roundkeys[0], "00", "00", "00"])
    w[4] = xorArrayOfHexStrings(w[4], w[0].copy())
    roundIndex = 1
    for i in range(5, 44):
        if i % 4 == 0:
            w.append([])
            # circular left shitf
            w[i] = (circularLeftShift(w[i - 1].copy(), 1))
            # Substitute with Sbox
            w[i] = substituteByteWithSbox(w[i])
            # add round key
            w[i] = addRoundKey(w[i], [roundkeys[int(i / 4) - 1], "00", "00", "00"])
            # xor with g and 4 index left
            w[i] = xorArrayOfHexStrings(w[i], w[i - 4])
        else:
            w.append(xorArrayOfHexStrings(w[i - 1], w[i - 4]))

    return w

#encryption takes plain text(ascii string) and words list of list and return hex string of cypher text
def encryption(plainTextinput,w):
    cypher = []
    textLength = len(plainTextinput)
    global mainTextLength
    mainTextLength = textLength
    if textLength % 16 != 0 :
        plainTextinput += " "*(textLength - (textLength % 16))
    textLength = len(plainTextinput)
    for index in range(int(textLength/16)):
        plainText = plainTextinput[index*16 : (index*16)+16]

        #plainText to hex array
        pw = []
        index = 0
        for x in range(4):
            items = []
            for y in range(4):
                items.append(format(ord(plainText[index]), "x"))
                index += 1
            pw.append(items)
        plainTexthex=pw.copy()
        # making plain text colm matrix

        colmPW = []
        for i in range(len(pw[0])):
            temp = []
            for j in range(len(pw)):
                temp.append(pw[j][i])
            colmPW.append(temp)

        words = []
        for k in range(4):
            words.append(w[0 + k])

        # making word colm matrix
        colmW = []
        for i in range(len(w[0])):
            temp = []
            for j in range(len(w[0])):
                temp.append(words[j][i])
            colmW.append(temp)

        # add round key
        for i in range(4):
            colmPW[i] = xorArrayOfHexStrings(colmPW[i], colmW[i])

        # starting of rounds
        for m in range(1, 11):
            # substitute with sbox
            for i in range(4):
                colmPW[i] = substituteByteWithSbox(colmPW[i])

            # circular left shift
            for i in range(len(colmPW)):
                colmPW[i] = circularLeftShift(colmPW[i], i)

            # mix colm(colm multiplication) if not round 10
            # multiplier * colmPW
            if m != 10:
                multiplier = [["02", "03", "01", "01"], ["01", "02", "03", "01"], ["01", "01", "02", "03"],
                              ["03", "01", "01", "02"]]
                result = []
                for i in range(len(multiplier)):
                    item = ["0"] * len(colmPW[0])
                    result.append(item)
                for i in range(len(multiplier)):
                    for j in range(len(colmPW[0])):
                        for k in range(len(colmPW)):
                            bv1 = BitVector(hexstring=multiplier[i][k])
                            bv2 = BitVector(hexstring=colmPW[k][j])
                            bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                            bv3str = str(bv3)
                            bv3hex = hex(int(bv3str, 2))[2:]
                            if len(bv3hex) < 2:
                                bv3hex = "0" + bv3hex
                            result[i][j] = xorTwoHex(result[i][j], bv3hex)
                colmPW = result

            # add round key with plain text
            wordSelector = m * 4
            words = []
            for k in range(4):
                words.append(w[wordSelector + k])
            # making word colm matrix
            colmW = []
            for i in range(len(w[0])):
                temp = []
                for j in range(len(w[0])):
                    temp.append(words[j][i])
                colmW.append(temp)

            # add round key
            for i in range(4):
                colmPW[i] = xorArrayOfHexStrings(colmPW[i], colmW[i])
        # generating cypher text and make colm orientatin into row orientation
        # cypher = [] declared at starting of method
        for i in range(len(colmPW[0])):
            temp = []
            for j in range(len(colmPW)):
                temp.append(colmPW[j][i])
            cypher.append(temp)

    cypherinonestring=""
    for i in cypher:
        for j in i:
            cypherinonestring+=j
    return cypherinonestring.upper()


def encryptionHexText(plainTextinput,w):
    cypher = []
    textLength = len(plainTextinput)
    if textLength % 32 != 0 :
        plainTextinput += " "*(textLength - (textLength % 32))
    textLength = len(plainTextinput)
    for index in range(int(textLength/32)):
        plainText = plainTextinput[index*32 : (index*32)+32]

        #plainText to hex array
        pw = []
        index = 0
        for x in range(4):
            items = []
            for y in range(4):
                items.append(str(plainText[index]) + str(plainText[index+1]))
                index += 2
            pw.append(items)
        plainTexthex=pw.copy()
        # making plain text colm matrix
        colmPW = []
        for i in range(len(pw[0])):
            temp = []
            for j in range(len(pw)):
                temp.append(pw[j][i])
            colmPW.append(temp)

        words = []
        for k in range(4):
            words.append(w[0 + k])

        # making word colm matrix
        colmW = []
        for i in range(len(w[0])):
            temp = []
            for j in range(len(w[0])):
                temp.append(words[j][i])
            colmW.append(temp)

        # add round key
        for i in range(4):
            colmPW[i] = xorArrayOfHexStrings(colmPW[i], colmW[i])

        # starting of rounds
        for m in range(1, 11):
            # substitute with sbox
            for i in range(4):
                colmPW[i] = substituteByteWithSbox(colmPW[i])

            # circular left shift
            for i in range(len(colmPW)):
                colmPW[i] = circularLeftShift(colmPW[i], i)

            # mix colm(colm multiplication) if not round 10
            # multiplier * colmPW
            if m != 10:
                multiplier = [["02", "03", "01", "01"], ["01", "02", "03", "01"], ["01", "01", "02", "03"],
                              ["03", "01", "01", "02"]]
                result = []
                for i in range(len(multiplier)):
                    item = ["0"] * len(colmPW[0])
                    result.append(item)
                for i in range(len(multiplier)):
                    for j in range(len(colmPW[0])):
                        for k in range(len(colmPW)):
                            bv1 = BitVector(hexstring=multiplier[i][k])
                            bv2 = BitVector(hexstring=colmPW[k][j])
                            bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                            bv3str = str(bv3)
                            bv3hex = hex(int(bv3str, 2))[2:]
                            if len(bv3hex) < 2:
                                bv3hex = "0" + bv3hex
                            result[i][j] = xorTwoHex(result[i][j], bv3hex)
                colmPW = result

            # add round key with plain text
            wordSelector = m * 4
            words = []
            for k in range(4):
                words.append(w[wordSelector + k])
            # making word colm matrix
            colmW = []
            for i in range(len(w[0])):
                temp = []
                for j in range(len(w[0])):
                    temp.append(words[j][i])
                colmW.append(temp)

            # add round key
            for i in range(4):
                colmPW[i] = xorArrayOfHexStrings(colmPW[i], colmW[i])
        # generating cypher text and make colm orientatin into row orientation
        # cypher = [] declared at starting of method
        for i in range(len(colmPW[0])):
            temp = []
            for j in range(len(colmPW)):
                temp.append(colmPW[j][i])
            cypher.append(temp)

    cypherinonestring=""
    for i in cypher:
        for j in i:
            cypherinonestring+=j
    return cypherinonestring.upper()

#decryption takes hex string of cypheredtext and words and returns ascii string
def decryption(cypherTextstringInput,w):
    plainTextHex = []
    textLength = len(cypherTextstringInput)
    if textLength % 2 != 0:
        cypherTextstringInput  = "0" + cypherTextstringInput
    textLength = len(cypherTextstringInput)
    for index in range(int(textLength / 32)):
        cypherTextstring = cypherTextstringInput[index * 32: (index * 32) + 32]
        cypherText = splitHexString(cypherTextstring)
        #create colmPlaintextWord from cypher text
        colmPW = []
        for i in range(len(cypherText[0])):
            temp = []
            for j in range(len(cypherText)):
                temp.append(cypherText[j][i])
            colmPW.append(temp)

            wordSelector = 10 * 4
            words = []
            for k in range(4):
                words.append(w[wordSelector + k])
            # making word colm matrix
            colmW = []
            for i in range(len(w[0])):
                temp = []
                for j in range(len(w[0])):
                    temp.append(words[j][i])
                colmW.append(temp)
        # add round key with wordclm of last used in encryption
        # add round key
        for i in range(4):
            colmPW[i] = xorArrayOfHexStrings(colmPW[i], colmW[i])

        for m in range(10, 0, -1):
            # inverse shift row
            for i in range(len(colmPW)):
                colmPW[i] = circularRightShift(colmPW[i], i)

            # inverse sub box substitute
            for i in range(4):
                colmPW[i] = substituteByteWithInverseSbox(colmPW[i])

            # add round key
            wordSelector = m * 4
            words = []
            for k in range(4, 0, -1):
                words.append(w[wordSelector - k])
            # making word colm matrix
            colmW = []
            for i in range(len(w[0])):
                temp = []
                for j in range(len(w[0])):
                    temp.append(words[j][i])
                colmW.append(temp)

            # add round key
            for i in range(4):
                colmPW[i] = xorArrayOfHexStrings(colmPW[i], colmW[i])

            if m != 1:
                # inverse mix column
                multiplier = [["0e", "0b", "0d", "09"], ["09", "0e", "0b", "0d"], ["0d", "09", "0e", "0b"],
                              ["0b", "0d", "09", "0e"]]
                result = []
                for i in range(len(multiplier)):
                    item = ["0"] * len(colmPW[0])
                    result.append(item)
                for i in range(len(multiplier)):
                    for j in range(len(colmPW[0])):
                        for k in range(len(colmPW)):
                            bv1 = BitVector(hexstring=multiplier[i][k])
                            bv2 = BitVector(hexstring=colmPW[k][j])
                            bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                            bv3str = str(bv3)
                            bv3hex = hex(int(bv3str, 2))[2:]
                            if len(bv3hex) < 2:
                                bv3hex = "0" + bv3hex
                            result[i][j] = xorTwoHex(result[i][j], bv3hex)
                colmPW = result
        #make plain text converting colm orientation to row orientation
        # plainTextHex = []
        for i in range(len(colmPW[0])):
            temp = []
            for j in range(len(colmPW)):
                temp.append(colmPW[j][i])
            plainTextHex.append(temp)
    cypherinonestring = ""
    for i in plainTextHex:
        for j in i:
            if (int(len(cypherinonestring)/2) )>= mainTextLength:
                break
            cypherinonestring += j

    return cypherinonestring

        # plainTextascii = ""
        # for i in plainTextHex:
        #     for j in range(len(plainTextHex)):
        #         plainTextascii += (bytes.fromhex(i[j]).decode('utf-8'))
        # return plainTextascii


#char key and char plaintext
def asciiKeyAsciiPlain(asciiKey,asciiTexts):
    keyLength = 16
    # key Scheduling
    startTime = time.time()
    roundKey = generateRoundKeys()
    wordss = generateKeyWords(asciiKey, keyLength, roundKey)
    keySchedulingTime = time.time() - startTime

    # encryption
    startTime = time.time()
    cypherTexts = encryption(asciiTexts, wordss.copy())
    encryptionTime = time.time() - startTime

    # decryption
    startTime = time.time()
    decypheredTexthex = decryption(cypherTexts, wordss.copy())
    decryptionTime = time.time() - startTime
    print("Keys :\n", asciiKey, "[in ascii]")
    print(charToHexString(asciiKey), "[in hex]")
    print("\nPlain text :\n", asciiTexts, "[in ascii]")
    print(charToHexString(asciiTexts), "[in hex]")
    print("\nCypher text : \n", cypherTexts, "[in hex]")
    print(hexArrayToCharOneString(cypherTexts), "[in ascii]")
    print("\nDecyphered Text :\n", decypheredTexthex, "[in hex]")
    print(hexArrayToCharOneString(decypheredTexthex), "[in ascii]")

    print("Execution Time")
    print("Key Scheduling : ", keySchedulingTime)
    print("Encryption Time : ", encryptionTime)
    print("Decryption Time : ", decryptionTime)


#input hex key and hex cypher
def hexKeyAndHexCypher(hexKey,hexCypher):
    keyLength = 16
    keyInHex = hexKey
    key = hexArrayToCharOneString(keyInHex)
    # key Scheduling
    startTime = time.time()
    roundKey = generateRoundKeys()
    wordss = generateKeyWords(key, keyLength, roundKey)
    keySchedulingTime = time.time() - startTime

    cypherTexts = hexCypher
    # cypherTexts = "182e0afe67094cb70f2a7dc74f7e0076552456c820d6029f9519a7f8a020a6dc6707ec0f7e1eb439f3ea0db53ee60c958d67693151bba8ec61dacbd83e99c6ef9daa26069685e2284ba264a9b7ad9a56d6203cc8ab315c34de944af524b12d6585ccfb0c6fab4b7006266d66280ad44ea44dbe21d269f3e030129f49851711a6dd7b9f55dfd4c5dcee355973fc2ce6486d7df8de352e73d434ee9932477226e42012d10b974dfa66366f9830b0fb62e69dfde63105ae1d2eccb316e4f57ceb55eef9677d5dc267f8ece3d2fa30d2c06c"

    # decryption
    startTime = time.time()
    decypheredTexthex = decryption(cypherTexts, wordss.copy())
    decryptionTime = time.time() - startTime
    print("Keys :\n", key, "[in ascii]")
    print(hexKey, "[in hex]")
    print("\nCypher text : \n", cypherTexts, "[in hex]")
    print(hexArrayToCharOneString(cypherTexts), "[in ascii]")
    print("\nDecyphered Text :\n", decypheredTexthex, "[in hex]")
    print(hexArrayToCharOneString(decypheredTexthex), "[in ascii]")

    print("Execution Time")
    print("Key Scheduling : ", keySchedulingTime)
    print("Decryption Time : ", decryptionTime)


def asciiKeyAndFileText(asciiKey,fileName):
    file = open("file.py", "rb")
    keyLength = 16
    key = asciiKey
    plainTexts = hexArrayToCharOneString(file.read().hex())

    # key Scheduling
    startTime = time.time()
    roundKey = generateRoundKeys()
    wordss = generateKeyWords(key, keyLength, roundKey)
    keySchedulingTime = time.time() - startTime

    # encryption
    startTime = time.time()
    cypherTexts = encryption(plainTexts, wordss.copy())
    encryptionTime = time.time() - startTime

    # decryption
    startTime = time.time()
    decypheredTexthex = decryption(cypherTexts, wordss.copy())
    decryptionTime = time.time() - startTime
    file = open("new"+fileName, "w")
    file.write(hexArrayToCharOneString(decypheredTexthex))
    print("Keys :\n", key, "[in ascii]")
    print(charToHexString(key), "[in hex]")
    print("\nPlain text :\n", plainTexts, "[in ascii]")
    print(charToHexString(plainTexts), "[in hex]")
    print("\nCypher text : \n", cypherTexts, "[in hex]")
    print(hexArrayToCharOneString(cypherTexts), "[in ascii]")
    print("\nDecyphered Text :\n", decypheredTexthex, "[in hex]")
    print(hexArrayToCharOneString(decypheredTexthex), "[in ascii]")

    print("Execution Time")
    print("Key Scheduling : ", keySchedulingTime)
    print("Encryption Time : ", encryptionTime)
    print("Decryption Time : ", decryptionTime)


mainTextLength = 0
keyLength = 16
#asciiKeyAsciiPlain("BUET CSE16 Batch","WillGraduateSoon")
# hexKeyAndHexCypher("hexKey","hexCypher")
asciiKeyAndFileText("abcdefghijklmnopqrstd","file.py")
# file = open("file.py","rb")

# #key = "BUET CSE16 Batch"
# #key=input("enter 16 byte key")
#
# keyInHex = "44656372797074205461736b20536978"
# key = hexArrayToCharOneString(keyInHex)
#
# #plainTexts="WillGraduateSoon"
# #plainTexts=input("enter plain text")
#
# plainTexts =hexArrayToCharOneString(file.read().hex())
#
# #key Scheduling
# startTime = time.time()
# roundKey = generateRoundKeys()
# wordss = generateKeyWords(key,keyLength,roundKey)
# keySchedulingTime = time.time() - startTime
#
# #encryption
# startTime = time.time()
# cypherTexts = encryption(plainTexts,wordss.copy())
# #cypherTexts = "182e0afe67094cb70f2a7dc74f7e0076552456c820d6029f9519a7f8a020a6dc6707ec0f7e1eb439f3ea0db53ee60c958d67693151bba8ec61dacbd83e99c6ef9daa26069685e2284ba264a9b7ad9a56d6203cc8ab315c34de944af524b12d6585ccfb0c6fab4b7006266d66280ad44ea44dbe21d269f3e030129f49851711a6dd7b9f55dfd4c5dcee355973fc2ce6486d7df8de352e73d434ee9932477226e42012d10b974dfa66366f9830b0fb62e69dfde63105ae1d2eccb316e4f57ceb55eef9677d5dc267f8ece3d2fa30d2c06c"
# encryptionTime = time.time() - startTime
#
# #decryption
# startTime = time.time()
# decypheredTexthex = decryption(cypherTexts,wordss.copy())
# decryptionTime = time.time() - startTime
# file = open("newfile.py","w")
# file.write(hexArrayToCharOneString(decypheredTexthex))
# print("Keys :\n",key,"[in ascii]")
# print(charToHexString(key),"[in hex]")
# print("\nPlain text :\n",plainTexts,"[in ascii]")
# print(charToHexString(plainTexts),"[in hex]")
# print("\nCypher text : \n",cypherTexts,"[in hex]")
# print(hexArrayToCharOneString(cypherTexts),"[in ascii]")
# print("\nDecyphered Text :\n",decypheredTexthex,"[in hex]")
# print(hexArrayToCharOneString(decypheredTexthex),"[in ascii]")
#
# print("Execution Time")
# print("Key Scheduling : ",keySchedulingTime)
# print("Encryption Time : ",encryptionTime)
# print("Decryption Time : ",decryptionTime)

