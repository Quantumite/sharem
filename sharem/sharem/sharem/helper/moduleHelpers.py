import json


def readDLLsAddsFromFile(foundDLLAddrs, export_dict):
    try:
        with open(foundDLLAddrs, "r") as f:
            export_dict = json.load(f)
        return export_dict
    except Exception as e:
        # print ("this is the traceback:")
        # print(traceback.format_exc())
        # print("error:",e)
        return {}


def insertIntoBytes(binaryBlob, start, size, value):
    lBinary = list(binaryBlob)
    for x in range(size):
        lBinary.insert(start, value)
    final = bytes(lBinary)
    return final
