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
VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1", "TLSv1.2", "TLSv1.3"]

# Storage
DATA_STORE = {}

### Helper
# Generate a the powerset to a given list of ports
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


# Write given data into a .csv
def writeData(outputDir, ip, ports, cipherList):
    outputFile = outputDir + "gesamt.csv"
    f = open(outputFile, "a")
    line = ip + ";" + ",".join(ports) + ";" + ",".join(cipherList) + "\n"
    f.write(line)
    f.close()    
    return 0

# Merge gathered data into the correct ip<->port<->cipher mapping
def mergeData(outputDir):
    for ip in DATA_STORE:
        portList = []
        usedCiphers = []
        for port in DATA_STORE[ip]:
            portList.append(port)
        # Generate the powerset of portList and sort elements with cardinality=1 in the correct order
        # sort
        n = len(portList)
        i = 2**n - (n + 1)
        # powerset
        pListPowerSet = powerset(portList)[::-1]
        pListPowerSet = pListPowerSet[:i] + pListPowerSet[i:][::-1]
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
                writeData(outputDir, ip, list(portSubset), intersec)

# Parse a testssl.sh report's data
# TODO: testssl.sh Output nicht immer gleich, betrifft: @PRIO
#       - .html
#       - .json
#   Woran liegt das? => Informationen in README.md aufnehmen
def parseFile(fileName, dirName, versionFilter):
    fName, fType = os.path.splitext(fileName)
    filePath = dirName + fName + fType
    f = open(filePath, "r")

    ip, port = fileName.split("-")[0].split("_")
    ports = {}

    # .html-Parser
    if fType == ".html":
        cipherBuffer = ""
        writeToBuffer = False
        for line in f:
            line = line.strip()
            # TODO: schöner machen
            if "ALL" not in versionFilter:
                if len(versionFilter) > 1:
                    # parse for multiple versions
                    version = re.search(r"[LST]{3}v([0-9]\.[0-9]|[0-9])", line)
                    if version != None:
                        version = version.group()
                        if version in versionFilter:
                            writeToBuffer = True
                        elif version not in versionFilter:
                            writeToBuffer = False
                # parse for a single version
                elif line.startswith(FILTER_START_TAG + versionFilter + FILTER_END_TAG):
                    writeToBuffer = True
                elif line.startswith(FILTER_START_TAG) and not line.endswith(versionFilter + FILTER_END_TAG):
                    writeToBuffer = False
            # parse for all versions
            elif line.startswith(FILTER_START_TAG + "SSLv2" + FILTER_END_TAG):
                # TODO: Was ist, wenn SSLv2 nicht mehr drin steht?
                writeToBuffer = True
            elif line.strip() == "":
                writeToBuffer = False
            else:
                print("An error occurred while parsing: no matching version found (" + versionFilter + ")")
            
            if writeToBuffer:
                cipherBuffer += line
        # Check for cipher suite string in row
        cipherList = []
        for match in re.finditer(r"TLS_([A-Z0-9]*_)*[A-Z0-9]*", cipherBuffer):
            cipherList.append(match.group())
        
        if str(ip) in DATA_STORE.keys():
            ports = DATA_STORE[str(ip)]
        ports[str(port)] = cipherList
        DATA_STORE[str(ip)] = ports
    # TODO: JSON-Parser
    else:
        print("An error occurred while parsing: Unsupported file type for given input file (" + fileName + ")")
    f.close()

# Evaluate parsed ciphers by requesting the ciphersuite.info api
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
                            print("An error occurred while evaluating: Unknow security value returned by API (" + secVal + ")")
                    else:
                        print("Request failed for cipher: " + cipher)
                        print(r.status_code)
                        print(r.text)

### Main
if __name__ == "__main__":
    versionFilter = []
    outputDir = "./"
    inputFile = ""
    inputDir = ""

    # Parse arguments
    if "h" in sys.argv:
        # TODO: Zusatzinformationen für Format-Fehler
        print("USAGE: python3 generateReport.py [OPTIONS]")
        print()
        print("With OPTIONS:")
        print()
        print("h: Help output")
        print("v: SSL/TLS versions")
        print(" : - \"ALL\"")
        print(" : - one or more from \"SSLv2\", \"SSLv3\", \"TLSv1\", \"TLSv1.1\", \"TLSv1.2\", \"TLSv1.3\"")
        print("o: Output directory (current directory if empty)")
        print("d: Input directory")
        print("f: Input file")
        print("")
        print("Example:")
        print("python3 generateReport.py v SSLv2,SSLv3,TLSv1 o ./output/ d ./input/")
    else:
        # SSL/TLS Version
        if "v" in sys.argv:
            versionList = sys.argv[sys.argv.index("v")+1].split(",")
            for version in versionList:
                if version not in VERSIONS:
                    print("An error occurred while parsing the arguments: Unsopported SSL/TLS Version (" + version + ")")
                else:
                    versionFilter.append(version)
        else:
            versionFilter = ["ALL"]
        # Output-Directory
        if "o" in sys.argv:
            outputDir = sys.argv[sys.argv.index("o")+1]
            if os.path.isdir(outputDir):
                if not outputDir.endswith("/"):
                    outputDir += "/"
            else:
                print("An error occurred while parsing the arguments: Invalid output directory (" + outputDir + ")")
        # Input-Directory
        if "d" in sys.argv:
            inputDir = sys.argv[sys.argv.index("d")+1]
            if os.path.isdir(inputDir):
                if not inputDir.endswith("/"):
                    outputDir += "/"
                for f in os.listdir(inputDir):
                    print("Processing: " + f)
                    parseFile(f, inputDir, versionFilter)
                evaluateCiphers()
                mergeData(outputDir)
            else:
                print("An error occurred while parsing the arguments: Invalid output directory (" + inputDir + ")")
        # Input-File
        elif "f" in sys.argv:
            inputFile = sys.argv[sys.argv.index("f")+1]
            # TODO: prüfen, ob file existiert
            # TODO: @errorHandling => File nicht auffindbar
            print("Parsing single files is currently not supported. Please use OPTION d instead.")
        else:
            print("An error occurred while parsing the arguments: No input source given")