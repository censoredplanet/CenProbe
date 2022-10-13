import sys
import time
import random
import argparse
import subprocess 
from multiprocessing import Pool

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hostlist')
    parser.add_argument('outdir')
    parser.add_argument('-v6', '--version_6', action='store_true')
    parser.add_argument('-nt', '--n_threads', default=10, type=int)
    args = parser.parse_args()

    hl = load_hostlist(args.hostlist)
    fingerprint_all_hosts(hl, args.n_threads, args.outdir, args.version_6)

def fingerprint_all_hosts(hl, n_threads, outdir, v6=False):
    pool = Pool(processes=n_threads)
    results = [pool.apply_async(fingerprint_host, (h, outdir, v6)) for h in hl]
    pool.close()
    pool.join()

    results = [res.get() for res in results]

    return results

def fingerprint_host(host, outdir, v6=False):
    print('fingerprinting: {0}'.format(host))
    try:
        if v6:
            v6flag = '-6'
        else:
            v6flag = ''
        nmap = f'sudo nmap {v6flag} -O --max-os-tries 3 -d -v {host} > {outdir}/nmap_{host}_fingerprint.txt 2>/dev/null'
        nmap_proc  = subprocess.run(nmap, shell=True)
    except Exception as e:
        print(e)

def load_hostlist(hostlist):
    ips = set()
    with open(hostlist, 'r') as f:
        for line in f:
            ip = line.strip().split(',')[0]
            ips.add(ip)
    
    ips = list(ips)
    random.shuffle(ips)
    return ips 
if __name__ == '__main__':
    main()
