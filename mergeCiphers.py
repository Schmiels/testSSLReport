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
# @solved: Format ist default-Output

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

# Reading Data from previous output files
def readData(inputDir):
    data = {}
    # Read all files in given directory
    for f in os.listdir(inputDir):
        ports = {}
        prefix = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}_p[0-9]{1,5}", f)
        # determine if ip or hostname
        if prefix == None:
            prefix = re.search(r"([a-z0-9]*\.)*[a-z]*_p[0-9]{1,5}", f)

        if prefix == None:
            print("No macht found for " + f)
        else:
            prefix = prefix.group()
        
        # TODO: Error-Handling für incorrect file name formate
        ip, port = prefix.split("_")
        ciphers = []
        # build cipher list
        for line in open(inputDir + f, "r"):
            ciphers.append(line.strip())
        if str(ip) in data.keys():
            ports = data[str(ip)]
        # build complete list
        ports[str(port)] = ciphers
        data[str(ip)] = ports
        
    return data

# Merges given data by mapping ciphers to ports to ips
def mergeData(data):
    for ip in data:
        portList = []
        usedCiphers = []
        for port in data[ip]:
            portList.append(port)
        # TODO: richtige Reihenfolge für die 1er Teilmengen?
        pListPowerSet = powerset(portList)[::-1]
        # convert list into correct port-cipher mapping by filtering with given subsets
        for portGroup in pListPowerSet:
            concatted = []
            intersec = []
            for port in portGroup:
                concatted.append(data[ip][port])
            intersec = list(set.intersection(*[set(x) for x in concatted]))
            if len(intersec) > 0:
                for cipher in intersec:
                    if cipher in usedCiphers:
                        intersec.remove(cipher)
                    else:
                        usedCiphers.append(cipher)
                writeData(ip, list(portGroup), intersec)

    return 0

# Writes data into .csv
# TODO: output-Parameter
# TODO: vor/nach dem Schreiben irgendwie sortieren
#       - portList
#       - IPs
def writeData(ip, ports, cipherList):
    outputFile = "./testData/output/gesamt.csv"
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
        merged = mergeData(data)
    else:
        print("Invalid arguments")