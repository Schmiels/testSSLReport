# Imports
import sys
import os
import requests
import re

# TODO: Daten zu einer IP sammeln -> für Ports zusammenführen -> alle Daten zu allen IPs in eine csv schreiben mit ip;port,port,port;cipher,cipher,cipher
# TODO: vllt lieber sets als Listen
# TODO: Input-directory
# TODO: Parameter für Ausgabe von "*_secure.txt"
# TODO: Parsen der Argumente verbessern (Exceptions?)
# TODO: vernünftiger Output bei der Verarbeitung (verbose Parameter?)

API_URL = "https://ciphersuite.info/api/cs/"
DATA_PARAM = "security"
FILTER_START_TAG = "<u>"
FILTER_END_TAG = "</u>"
VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
OUTPUTLOCATION = "./testData/output/"

### Helper
def parseFile(fileType, fileName, dirName, versionFilter):
    # WORKAROUND
    f = open(dirName + fileName + fileType, "r")
    # OLD
    # f = open(fileName + fileType, "r")
    # DEBUG
    print(versionFilter)
    if fileType == ".html":
        cipherBuffer = ""
        writeToBuffer = False
        for line in f:
            # TODO: schöner machen
            # Will only work as long as SSLv2 is listed by testssl.sh
            if versionFilter != "ALL":
                if line.startswith(FILTER_START_TAG + versionFilter + FILTER_END_TAG):
                    writeToBuffer = True
                elif line.startswith(FILTER_START_TAG) and not line.endswith(versionFilter + FILTER_END_TAG):
                    writeToBuffer = False
            elif line.startswith(FILTER_START_TAG + VERSIONS[0] + FILTER_END_TAG):
                writeToBuffer = True
            elif line.strip() == "":
                writeToBuffer = False
            if writeToBuffer:
                cipherBuffer += line
        # Check for Cipher Suite String in Row
        cipherList = []
        for match in re.finditer(r"TLS_([A-Z0-9]*_)*[A-Z0-9]*", cipherBuffer):
            cipherList.append(match.group())

        cipherList = list(dict.fromkeys(cipherList))
    # TODO: JSON-Parser
    else:
        print("Script currently only supports .html-Files")

    f.close()
    return cipherList 

def evaluateCiphers(fileName, dirName, versionFilter):
    fName, fType = os.path.splitext(fileName)
    cipherList = parseFile(fType, fName, dirName, versionFilter)
    
    if len(cipherList) > 0:
        # TODO: Schöner machen
        outputPrefix = re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}_p[0-9]{1,5}", fName)
        fileNameError = False
        if outputPrefix == None:
            outputPrefix = re.search(r"([a-z0-9]*\.)*[a-z]*_p[0-9]{1,5}", fName)
            if outputPrefix == None:
                fileNameError = True

        if fileNameError:
            print("Unsupported file name format for: " + fileName)
            print("Processing for " + fileName + " canceled")
            return None
        else:
            outputPrefix = outputPrefix.group()

        weakF = open(OUTPUTLOCATION + outputPrefix + "_weak.txt", "w")
        # TODO: enable via param 
        # secureF = open(OUTPUTLOCATION + outputPrefix + "_secure.txt", "w")

        for cipher in cipherList:
            requestsUrl = API_URL + cipher + "/"
            r = requests.get(requestsUrl)
            if r.ok:
                secVal = r.json()[cipher][DATA_PARAM]
                if secVal == "insecure" or secVal == "weak":
                    weakF.write(cipher + "\n")
                # TODO: enable via param
                # elif secVal == "secure" or secVal == "recommended":
                #    secureF.write(cipher + "\n")
                else:
                    print("Unsupported " + DATA_PARAM + " value: " + secVal)
            else:
                print("Request failed for cipher:" + cipher)
                print(r.status_code)
                print(r.text)

        weakF.close()
        # TODO: enable via param
        # secureF.close()

### Main
if __name__ == "__main__":
    fileName = ""
    dirName = ""

    # Parse arguments
    if len(sys.argv) > 1:
        # TODO: Help-Output
        # if sys.argv[1] == "-h" | "--help"
        #    print("")
        # TODO: parse parameters => execute evaluateCiphers
        # Filter SSL/TLS Version
        if "v" in sys.argv:
            versionFilter = sys.argv[sys.argv.index("v")+1]
            if versionFilter not in VERSIONS:
                print("Unsupported SSL/TLS Version: " + versionFilter)
                exit(0)
        else:
            versionFilter = "ALL"
        # Scan given directory
        if "d" in sys.argv:
            dirName = sys.argv[sys.argv.index("d")+1]

            for f in os.listdir(dirName):
                # TODO: Verschiedene FileTypes implementieren (json)
                if f.endswith(".html"):
                    print("Processing: " + f)
                    evaluateCiphers(f, dirName, versionFilter)
        elif "f" in sys.argv:
            # TODO: muss wahrscheinlich überarbeitet werden
            fileName = sys.argv[sys.argv.index("f")+1]
            print("Processing: " + fileName) 
            evaluateCiphers(f, dirName, versionFilter)
    else:
        print("Invalid arguments")