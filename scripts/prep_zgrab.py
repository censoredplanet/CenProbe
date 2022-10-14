import argparse
import sys

import json
import csv

AVAILABLE_ZGRAB_MODULES = ("http","https","imap","ftp","ntp","pop3","telnet","smtp","ssh")

def main(filename, out):
    protocol_to_ip = {}
    ip_to_protocol = {}
    writer = csv.writer(out)
    columns = set()
    with open(filename) as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            ip = row[0]
            ports = json.loads(row[1])
            if ports is None:
                continue
            for protocol in ports:
                if protocol is None:
                    continue
                protocol = tuple(protocol)
                if protocol not in protocol_to_ip:
                    protocol_to_ip[protocol] = []
                protocol_to_ip[protocol].append(ip)
                name = protocol[1]
                if name in AVAILABLE_ZGRAB_MODULES:
                    columns.add(name)
            if any([p[1] in AVAILABLE_ZGRAB_MODULES for p in ports]):
                ip_to_protocol[ip] = ports
    for ip, protocols in ip_to_protocol.items():
        row = [ip, ""]
        for proto in columns:
            if any([p[1] == proto for p in protocols]):
                writer.writerow(row + [proto])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--nmap_csv", type=str, help="file to read nmap metadata from")
    parser.add_argument("-o", "--outfile", type=str)
    args = parser.parse_args()

    if args.nmap_csv is None:
        logging.error("Must provide --nmap_csv.")
        exit(1)

    stdout = sys.stdout
    if args.outfile:
        stdout = open(args.outfile, "w")
    main(args.nmap_csv, stdout)


