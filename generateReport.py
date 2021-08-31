# TODO: Polished Code hier zusammenfügen
# TODO: sauberes Error-Hanling implementieren
# TODO: saubere Code-Doku
# TODO: saubere CLI

# Imports
import sys
import os
import requests
import re
from itertools import chain, combinations

### Globals
API_URL = "https://ciphersuite.info/api/cs/"
DATA_PARAM = "security"

# HTML-Parser
FILTER_START_TAG = "<u>"
FILTER_END_TAG = "</u>"

DATA_STORE = {}


### Helper

#######################
#### ErrorHandling #### TODO: Geeignete Lib?
#######################

#######################
### Powerset Helper ### powerset@mergeCiphers.py
#######################
def powerset(portList):
    sList = []
    # Convert port format to int
    pList = []
    for port in portList:
        pList.append(int(port[1:]))
    pList.sort()
    # Sort given portlist
    while len(portList) != 0:
        for port in portList:
            if int(port[1:]) == pList[0]:
                sList.append(port)
                portList.remove(port)
                pList.remove(int(port[1:]))
    # Generate powerset
    return list(chain.from_iterable(combinations(sList, r) for r in range(len(sList) + 1)))[1:]


#######################
### Zeile schreiben ### writeData@mergeCiphers.py
#######################
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

#######################
##### Zeile lesen ##### readData@mergeCiphers.py
####################### @deprecated

#######################
#### Daten mergen ##### mergeData@mergeCiphers.py
#######################
def mergeData():
    for ip in DATA_STORE:
        portList = []
        usedCiphers = []
        for port in DATA_STORE[ip]:
            portList.append(port)
        # TODO: richtige Reihenfolge für die 1er Teilmengen?
        #   - die letzten n ports reversen? auf pListPowerSet anwenden
        #       - smarte commands auf Liste und wieder zusammenfügen
        #       => liste = liste[:n] + liste[n::-1]
        pListPowerSet = powerset(portList)[::-1]
        # Convert list into correcet port-cipher mapping by filtering with given subsets
        for portSubset in pListPowerSet:
            concatted = []
            intersec = []
            for port in portSubset:
                concatted.append(DATA_STORE[ip][port])
            intersec = list(set.intersection(*[set(x) for x in concatted]))
            if len(intersec) > 0:
                for cipher in intersec:
                    if cipher in usedCiphers:
                        intersec.remove(cipher)
                    else:
                        usedCiphers.append(cipher)
                writeData(ip, list(portSubset), intersec)

    return 0


#######################
#### Report parsen #### parseFile@check_ciphers.py
#######################
def parseFile(fileName, dirName, versionFilter):
    fName, fType = os.path.splitext(fileName)
    filePath = dirName + "/" + fName + fType
    f = open(filePath, "r")

    ip, port = fileName.split("-")[0].split("_")
    ports = {}

    # .html-Parser
    if fType == ".html":
        cipherBuffer = ""
        writeToBuffer = False
        for line in f:
            # TODO: schöner machen
            if "ALL" not in versionFilter:
                if len(versionFilter) > 1:
                    # TODO: mehrere Versionen @PRIO
                    pass
                # else:
                elif line.startswith(FILTER_START_TAG + versionFilter + FILTER_END_TAG):
                    writeToBuffer = True
                elif line.startswith(FILTER_START_TAG) and not line.endswith(versionFilter + FILTER_END_TAG):
                    writeToBuffer = False
            elif line.startswith(FILTER_START_TAG + "SSLv2" + FILTER_END_TAG):
                # TODO: Was ist, wenn SSLv2 nicht mehr drin steht?
                writeToBuffer = True
            elif line.strip() == "":
                writeToBuffer = False
            else:
                # TODO: @errorHandling => Fehler beim Parsen (SSL/TLS Version nicht gefunden)
                pass
            
            if writeToBuffer:
                cipherBuffer += line
        # Check for cipher suite string in row
        cipherList = []
        for match in re.finditer(r"TLS_([A-Z0-9]*_)*[A-Z0-9]*", cipherBuffer):
            cipherList.append(match.group())
        
        # NEW
        if str(ip) in DATA_STORE.keys():
            ports = DATA_STORE[str(ip)]
        ports[str(port)] = cipherList
        DATA_STORE[str(ip)] = ports
    # TODO: JSON-Parser
    else:
        # TODO: @errorHandling => Nicht unterstützter Datei-Typ
        pass
    
    f.close()
    return 0

#######################
### Ciphers checken ### evaluateCiphers@check_ciphers.py
#######################
# TODO: Muss komplett umgeschrieben werden => neuer Aufbau von DATA_STORE
# def evaluateCiphers(fileName, dirName, versionFilter):
def evaluateCiphers():  
    if len(DATA_STORE) > 0:      
        # Check ciphers' security status
        for ip in DATA_STORE:
            for port in DATA_STORE[ip]:
                for cipher in DATA_STORE[ip][port]:
                    requestUrl = API_URL + cipher + "/"
                    r = requests.get(requestUrl)
                    if r.ok:
                        secVal = r.json()[cipher][DATA_PARAM]
                        if secVal == "insecure" or secVal == "weak":
                            # TODO: braucht man das?
                            pass
                        elif secVal == "secure" or secVal == "recommended":
                            DATA_STORE[ip][port].remove(cipher)
                        else:
                            # TODO: @errorHandling => Unsupported security value (secVal)
                            pass
                    else:
                        # TODO: @errorHandling => Request failed for cipher (r.status_code, r.text)
                        pass

    # return cipherOutput
    return 0

### Main
if __name__ == "__main__":
    versionFilter = ""
    outputDir = ""
    inputFile = ""
    inputDir = ""

    # Parse arguments
    #########################
    ### ARGUMENT HANDLING ### main@check_ciphers.py
    #########################
    if "h" in sys.argv:
        # TODO: Zusatuinformationen für Format-Fehler
        print("USAGE: python3 generateReport.py [OPTIONS]")
        print()
        print("With OPTIONS:")
        print()
        print("h: Help-Output")
        print("v: SSL/TLS-Versions")
        print(" : - \"ALL\"")
        print(" : - one or more from \"SSLv2\", \"SSLv3\", \"TLSv1.0\", \"TLSv1.1\", \"TLSv1.2\", \"TLSv1.3\"")
        print("o: Output-Directory (current directory if empty)")
        print("d: Input-Directory (current directory if empty)")
        print("f: Input-File")
    else:
        # SSL/TLS Version
        if "v" in sys.argv:
            versionFilter = sys.argv[sys.argv.index("v")+1].split(",")
            if versionFilter not in VERSIONS:
                # TODO: @errorHandling => ungültige SSL/TLS Version
                pass
        else:
            versionFilter = ["ALL"]
        # Output-Directory
        if "o" in sys.argv:
            outputDir = sys.argv[sys.argv.index("o")+1]
            # TODO: prüfen, ob directory existiert
            # TODO: @errorHandling => Directory nicht auffindbar
        # Input-Directory
        if "d" in sys.argv:
            inputDir = sys.argv[sys.argv.index("d")+1]
            # TODO: prüfen, ob directory existiert
            # TODO: @errorHandling => Directory nicht auffindbar
            for f in os.listdir(inputDir):
                print("Processing: " + f)
                parseFile(f, inputDir, versionFilter)
            evaluateCiphers()
            mergeData()
        # Input-File
        elif "f" in sys.argv:
            inputFile = sys.argv[sys.argv.index("f")+1]
            # TODO: prüfen, ob file existiert
            # TODO: @errorHandling => File nicht auffindbar
        else:
            # TODO: @errorHandling => Keine Inputquelle angegeben
            pass
    #########################
    #### GENERATE OUTPUT #### main@mergeCiphers.py
    #########################

    # DEV