# TODO: Daten aus Files in geeignete Ablage schreiben (dicts?)
#       - dict[ip][port] => set of ciphers (readData)
# TODO: Parsen der Argumente


# Imports
import sys
import os
import re
from itertools import chain, combinations

### Helper
# TODO: Was passiert, wenn Format != IP_pPORT ist?
# Creating a powerset
def powerset(portList):
    # Sort given portlist
    sList = []
    pList = []
    for port in portList:
        pList.append(int(port[1:]))
    pList.sort()
    while len(portList) != 0:
        for port in portList: 
            if int(port[1:]) == pList[0]:
                sList.append(port)
                portList.remove(port)
                pList.remove(int(port[1:]))
    # Generating powerset
    pSet = list(chain.from_iterable(combinations(sList, r) for r in range(len(sList) + 1)))[1:]
    return pSet

def sortPortlist(portList):
    sList = []
    pList = []
    for port in portList:
        pList.append(int(port[1:]))
    pList.sort()

    while len(portList) != 0:
        for port in portList: 
            if int(port[1:]) == pList[0]:
                sList.append(port)
                portList.remove(port)
                pList.remove(int(port[1:]))
    return sList

# Reading Data from previous output files
# ToBeDeleted: Funktionalität in check_ciphers implementieren => lesen der Daten nicht aus Dateien sondern aus gegebenen listen/sets
# @deprecated
def readData(inputDir):
    data = {}

    # ToBeDeleted
    for f in os.listdir(inputDir):
        ports = {}
        prefix = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}_p[0-9]{1,5}", f)
        if prefix == None:
            prefix = re.search(r"([a-z0-9]*\.)*[a-z]*_p[0-9]{1,5}", f)

        if prefix == None:
            print("No macht found for " + f)
        else:
            prefix = prefix.group()
        
        # TODO: Error-Handling für incorrect file name formate
        ip, port = prefix.split("_")
        ciphers = []
        # DEBUG
        # print(f)
        # print(ip)
        # print(port)
        # print("----")
        for line in open(inputDir + f, "r"):
            ciphers.append(line.strip())
        if str(ip) in data.keys():
            ports = data[str(ip)]
        ports[str(port)] = ciphers
        data[str(ip)] = ports
        
    return data

# Merges given data by mapping ciphers to ports to ips
# 
def mergeData(data):
    for ip in data:
        cipherList = []
        portList = []
        for port in data[ip]:
            portList.append(port)
            for cipher in data[ip][port]:
                cipherList.append(cipher)
        cipherList = list(dict.fromkeys(cipherList))
        
        #writeData(ip, portList, cipherList)

    for ip in data:
        portList = []
        usedCiphers = []
        for port in data[ip]:
            portList.append(port)
        pListPowerSet = powerset(portList)[::-1]
        # DEBUG
        print(pListPowerSet)
        # Match ciphers to ports
        for portGroup in pListPowerSet:
            


    return 0

# Writes data into .csv
# TODO: output-Parameter
# TODO: vor/nach dem Schreiben irgendwie sortieren
#       - portList
#       - IPs
def writeData(ip, ports, cipherList):
    outputFile = "./output/gesamt.csv"
    f = open(outputFile, "a")
    line = ip + ";" + ",".join(ports) + ";" + ",".join(cipherList) + "\n"
    f.write(line)
    f.close()    
    return 0

### Main
if __name__ == "__main__":
    if len(sys.argv) > 1:
        inputDir = sys.argv[1]
        data = readData(inputDir)
        #print(data['130.197.4.99'])
        merged = mergeData(data)
        #print(merged)
    else:
        print("Invalid arguments")
    # DEBUG
    # dict1 = {}
    # dict2 = {}
    # print(len(dict2))
    # dict2['443'] = ['123']
    # print(len(dict2))
    # print(dict2.keys())