"""
Usage: 

Analyzes nmap results from `nmap.py` to identify fingerprints on potential middleboxes.
"""

import os
import sys

import argparse
import csv
import glob
import json
import logging


def _port_from_line(line):
    if "/" not in line or not line[:line.find("/")].isnumeric():
        return None
    status = line.split()[1]
    service = line.split()[2]
    return int(line[:line.find("/")]), status, service


class NmapData(object):
    def __init__(self, filename):
        with open(filename) as f:
            self.raw_lines = f.readlines()
        self.open_ports = self._extract_open_ports()
        self.fingerprint = self._fingerprint_data()
        self.os_guess = self._os_guess()

    def _index_first_occurrence(self, search):
        for i, line in enumerate(self.raw_lines):
            if search in line:
                return i
        return None

    def _certain_os_guess(self):
        os_guess = self._index_first_occurrence("Device type")
        until = self._index_first_occurrence("TCP/IP fingerprint")
        data = ";".join([line.strip() for line in self.raw_lines[os_guess:until]])
        if os_guess is None or until is None:
            return None
        return data

    def _maybe_os_guess(self):
        os_guess = self._index_first_occurrence("Aggressive OS guesses")
        if os_guess is None:
            return None
        return self.raw_lines[os_guess]

    def _no_os_guess(self):
        os_guess = self._index_first_occurrence("No OS matches")
        os_guess2 = self._index_first_occurrence("Too many fingerprints match this host")
        return os_guess is not None or os_guess2 is not None

    def _os_guess(self):
        os_guess = self._certain_os_guess()
        if os_guess is not None:
            return os_guess
        os_guess = self._maybe_os_guess()
        if os_guess is not None:
            return os_guess
        if self._no_os_guess():
            return "No OS guess"
        return None


    def _extract_open_ports(self):
        port_line = self._index_first_occurrence("PORT ")
        if port_line is None:
            return None
        last_port_line = port_line + 1
        while _port_from_line(self.raw_lines[last_port_line]) is not None:
            last_port_line += 1
        all_ports = [_port_from_line(line) for line in self.raw_lines[port_line+1:last_port_line]]
        # return last_port_line - port_line
        return [(port, service) for port, status, service in all_ports if status == "open"]

    def _fingerprint_data(self):
        fingerprint_line = self._index_first_occurrence("TCP/IP fingerprint")
        if fingerprint_line is None:
            return None
        data = []
        for line in self.raw_lines[fingerprint_line+1:]:
            if len(line.strip()) == 0:
                break
            data.append(line.strip())
        return data


class CensysData(object):
    def __init__(self, data):
        self.raw_data = data

    def _as(self):
        return self.raw_data["autonomous_system"]["asn"]

    def as_desc(self):
        return self.raw_data["autonomous_system"]["description"]

    def location(self):
        return self.raw_data["location"]["registered_country"]

    def services(self):
        return [s["extended_service_name"] for s in self.raw_data["services"]]

    

def process_censys_data(filename):
    data = {}
    with open(filename) as f:
        for line in f:
            datum = json.loads(line.strip())
            data[datum["ip"]] = CensysData(datum)
    return data


def process_probe_csv(filename, data={}):
    protocol = "https" if "https" in filename else "http"
    with open(filename) as f:
        reader = csv.reader(f)
        next(reader, None) # Skip header
        for row in reader:
            ip, keyword, _, middlebox_ips, _ = row
            middlebox_ips = json.loads(middlebox_ips)
            for middlebox in middlebox_ips:
                if middlebox not in data:
                    data[middlebox] = []
                data[middlebox].append((ip, keyword, protocol))
    return data

def main(directory, censys_file, probe_csvs, out):
    csvwriter = csv.writer(out)
    header = ["IP address", "# open ports", "Nmap OS guess"]
    censys = None
    if censys_file is not None:
        censys = process_censys_data(censys_file)
        header += ["AS", "AS description", "Location", "Services open from Censys"]
    probe_data = {}
    if len(probe_csvs) > 0:
        for probe_csv in probe_csvs:
            probe_data = process_probe_csv(probe_csv[0], probe_data)
        header += ["HTTP Probes", "HTTPS Probes"]
    csvwriter.writerow(header)
    for filename in glob.glob(os.path.join(directory, "*_fingerprint.txt")):
        _, ip, _ = os.path.basename(filename).split("_")
        nmap_data = NmapData(filename)
        row = [ip, json.dumps(nmap_data.open_ports), nmap_data.os_guess]
        if censys is not None:
            if ip in censys:
                row += [censys[ip]._as(),
                censys[ip].as_desc(),
                censys[ip].location(),
                censys[ip].services()]
            else:
                row += ["", "", "", ""]
        if len(probe_data.keys()) > 0:
            probes = probe_data[ip] if ip in probe_data else []
            http_probes = [probe[:2] for probe in probes if probe[2] == "http"]
            https_probes = [probe[:2] for probe in probes if probe[2] == "https"]
            row += [http_probes, https_probes]
        csvwriter.writerow(row)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=str, help="directory to read files from")
    parser.add_argument("--censys", type=str, help="file for censys json data")
    parser.add_argument("--probes", action="append", nargs="+", help="probe CSV data")
    parser.add_argument("-o", "--outfile", type=str)

    parser.set_defaults(dir=None, censys=None, outfile=None, probes=[])
    args = parser.parse_args()
    if args.dir is None:
        logging.error("Must provide --dir.")
        exit(1)
    stdout = sys.stdout
    if args.outfile:
        stdout = open(args.outfile, "w")
    main(args.dir, args.censys, args.probes, stdout)

