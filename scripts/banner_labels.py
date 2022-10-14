import argparse
import json
import subprocess
import sys
import csv

import operator
from functools import reduce

data = {}

banner_keys = {
    "ftp": [("banner",)],
    "smtp": [("banner",)],
    "telnet": [("banner",)],
    "ssh": [("server_id","raw")],
    "http": [("response","body"), ("response", "server")],
    "tls": [("handshake_log", "server_certificates", "certificate", "parsed", "subject")],
}

manual_labels = {
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "ios-self-signed-": "cisco",
    "cisco": "cisco",
    "cscoe": "cisco",
    "user access verification": "cisco",
    "mikrotik": "mikrotik",
    "gw-ff1-mx960": "juniper",
    "global-protect": "palo alto"
}

# def testRecog(banner):
#     cmd = "./recog-go/recog_match ./recog/xml \"" + banner + "\""
#     output = !{cmd}
#     return output
    
def getLabel(banner):
    for l in manual_labels.keys():
        if l in str(banner).lower():
            #print(testRecog(banner[0]))
            return manual_labels[l]
    return None

def getFromDict(dataDict, keyList):
    try:
        return reduce(operator.getitem, keyList, dataDict)
    except KeyError:
        return None

def labels_from_zgrab(zgrab_file, csvwriter):
    labels = []
    with open(zgrab_file) as f:
        for line in f:
            o = json.loads(line)
            ip = o["ip"]
            if ip not in data:
                data[ip] = {}
            if "data" not in o:
                continue
            scans = o["data"].values()
            for scan in scans:
                protocol = scan["protocol"]
                status = scan["status"]
                if status != "success": continue
                paths = banner_keys[protocol]
                banners = [getFromDict(scan["result"], path) for path in paths]
                label = getLabel(banners)
                if label is not None:
                    labels.append((ip, protocol, label))#, json.dumps(banners)))
                data[ip][protocol] = (label, json.dumps(banners))
                if label is not None:
                    csvwriter.writerow([ip, protocol, label, json.dumps(banners)])
    return labels

def main(zgrab_file, out):
    writer = csv.writer(out)
    banners = labels_from_zgrab(zgrab_file, writer)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zgrab", type=str, help="JSON file from zgrab")
    parser.add_argument("-o", "--outfile", type=str)

    parser.set_defaults(zgrab=None, outfile=None)
    args = parser.parse_args()
    if args.zgrab is None:
        logging.error("Must provide --zgrab.")
        exit(1)
    stdout = sys.stdout
    if args.outfile:
        stdout = open(args.outfile, "w")
    main(args.zgrab, stdout)

