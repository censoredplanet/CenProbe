import argparse

import sys
import json
import time

import logging

from censys.search import CensysHosts


def main(filename, out):
    h = CensysHosts()
    with open(filename) as f:
        lines = f.readlines()

    for line in lines:
        ip = line.strip()
        host = h.view(ip)
        out.write(json.dumps(host))
        out.write("\n")
        time.sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--filename", type=str, help="file to read host IPs from")
    parser.add_argument("-o", "--outfile", type=str)
    args = parser.parse_args()

    if args.filename is None:
        logging.error("Must provide --filename.")
        exit(1)

    stdout = sys.stdout
    if args.outfile:
        stdout = open(args.outfile, "w")
    main(args.filename, stdout)


