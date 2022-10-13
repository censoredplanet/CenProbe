# CenProbe
This repository contains a set of scripts for actively probing and collecting data about particular network devices, including those that perform censorship. In here, we include a variety of scripts for collecting network features and banners from `nmap`, `zgrab2`, and performing light clustering and classification against the resulting data.

## Requirements
 * Install [Python v3.9](https://www.python.org/downloads/release/python-390/) or higher.
 * Install [Jupyter Notebook](https://jupyter.org/install), for instance using `pip install jupyter-notebook`.
 * Install the [`zgrab2`](https://github.com/zmap/zgrab2) command-line tool.
 * (Optional) Install and configure the [`censys-python`](https://github.com/censys/censys-python) package.

## Pipeline overview

```
# Input: host_list.txt
# Input: analyzed_output.csv

# 1. Nmap hosts
mkdir nmap_results
sudo python scripts/nmap_hosts.py host_list.txt nmap_results

# 2. Fetch Censys data
python scripts/fetch_censys_data.py --filename host_list --outfile censys_results.json

# 3. Summarize nmap, CenTrace, and Censys data
python scripts/nmap_analysis.py --dir nmap_results --censys censys_results.json --probes analyzed_output.csv --outfile nmap_analysis.csv

# 4. Banner grabs using zgrab
python scripts/prep_zgrab.py --nmap_csv nmap_analysis.csv | zgrab multiple -c zgrab.ini > zgrab_data.jsonl

5. Generating labels from Zgrab data
python scripts/banner_labels.py --zgrab_data zgrab_data.jsonl --outfile labels.csv
```

All of the above can be fed into the 

First, we identify the IP addresses that we want to probe and collect fingerprints from, for instance, using [CenTrace](https://github.com/censoredplanet/CenTrace).

1. Nmap hosts

```
sudo python scripts/nmap_hosts.py <HOST_LIST> <OUTDIR>
```

Requires `sudo`.  This script wraps around `nmap` and parallelizes OS fingerprinting for a list of hosts.
`HOST_LIST` should be the name of a file containing newline-separated IP addresses. `OUTDIR` should be the directory to store each of these results.

2. (Optional) Fetch Censys data

```
python scripts/fetch_censys_data.py --filename <HOST_LIST> --outfile <OUT_FILENAME>
```

Requires configuration of `censys-python` library via [`censys config`](https://censys-python.readthedocs.io/en/stable/quick-start.html).
`HOST_LIST` should be the name of a file containing newline-separated IP addresses. `OUT_FILENAME` should be the directory to store each of these results. If `--outfile` is omitted, will write to `stdout`.


3. Generate Nmap data summary

```
python scripts/nmap_analysis.py --dir <NMAP_DIR> --censys <CENSYS_FILE> --probes <CENTRACE_CSV> --outfile <OUT_CSV>
```
Summarizes relevant results from Nmap, CenTrace, and Censys into a single CSV. 
`NMAP_DIR` generated from step 1., `CENSYS_FILE` generated from 2., and `CENTRACE_CSV` generated from CenTrace.
`--censys` and `--probes` are optional arguments and can be omitted.
If `--outfile` is omitted, will write to `stdout`.

4. Banner grabs using Zgrab.
```
python scripts/prep_zgrab.py --nmap_csv <NMAP_CSV> | zgrab multiple -c zgrab.ini > <ZGRAB_OUT>
```
Requires zgrab CLI tool to be installed. `prep_zgrab.py` can also output to a file instead of `stdout` with `--outfile` argument.

5. Generating labels from Zgrab data
```
python scripts/banner_labels.py --zgrab <ZGRAB_OUT> --outfile <LABELS_CSV>
```

## Clustering

Run `jupyter notebook` and open `notebooks/cluster.ipynb`.


## Disclaimer
Russing `CenProbe` scripts from your machine may place you at risk if you use it within a highly censoring regime. `CenProbe` takes actions that try to trigger censoring middleboxes multiple times, and try to interfere with the functioning of the middlebox. Therefore, please exercice caution while using the tool, and understand the risks of running `CenProbe` before using it on your machine. Please refer to [our paper](https://ramakrishnansr.org/publications) for more information. 


## Data
The banner grabbing and active probing measurement data from the study in [our paper](https://ramakrishnansr.org/publications) can be found [here](https://drive.google.com/file/d/1begpJRkNfI8Rg378A1S0BQKVYrWFfuSa/view?usp=sharing). 

## Citation
If you use the `CenProbe` tool or data, please cite the following publication:
```
@inproceedings{sundararaman2022network,<br>
title = {Network Measurement Methods for Locating and Examining Censorship Devices},<br>
author = {Sundara Raman, Ram and Wang, Mona and Dalek, Jakub and Mayer, Jonathan and Ensafi, Roya},<br>
booktitle={In ACM International Conference on emerging Networking EXperiments and Technologies (CoNEXT)},<br>
year={2022}
```

## Licensing
This repository is released under the GNU General Public License (see [`LICENSE`](LICENSE)).

## Contact
Email addresses: `censoredplanet@umich.edu`, `ramaks@umich.edu`, `monaw@princeton.edu`, `jakub@citizenlab.ca`, `jonathan.mayer@princeton.edu`, and `ensafi@umich.edu`

## Contributors

[Mona Wang](https://github.com/m0namon)

[Ram Sundara Raman](https://github.com/ramakrishnansr)


