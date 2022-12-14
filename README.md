# CenProbe
[![DOI](https://zenodo.org/badge/550554376.svg)](https://zenodo.org/badge/latestdoi/550554376)

This repository contains a set of scripts for actively probing and collecting data about particular network devices, including those that perform censorship. In here, we include a variety of scripts for collecting network features and banners from `nmap`, `zgrab2`, and performing light clustering and classification against the resulting data.

## Requirements
 * Install [Python v3.9](https://www.python.org/downloads/release/python-390/) or higher.
 * Install [Jupyter Notebook](https://jupyter.org/install), for instance using `pip install jupyter-notebook`.
 * Install the [`zgrab2`](go get github.com/zmap/zgrab2) command-line tool.
 * (Optional) Install and configure the [`censys-python`](https://github.com/censys/censys-python) package.

## Pipeline overview

```
# Input: host_list.txt
# Input: analyzed_output.csv

# 1. Nmap hosts
mkdir nmap_results
sudo python3.9 scripts/nmap_hosts.py examples/host_list.txt nmap_results

# 2. Fetch Censys data
python3.9 scripts/fetch_censys_data.py --filename examples/host_list.txt --outfile examples/censys_results.json

# 3. Summarize nmap, CenTrace, and Censys data
python3.9 scripts/nmap_analysis.py --dir nmap_results --censys examples/censys_results.json --outfile examples/nmap_analysis.csv

# 4. Banner grabs using zgrab
python3.9 scripts/prep_zgrab.py --nmap_csv examples/nmap_analysis.csv | zgrab2 multiple -c config/zgrab.ini > examples/zgrab_data.jsonl
```


First, we identify the IP addresses that we want to probe and collect fingerprints from, for instance, using [CenTrace](https://github.com/censoredplanet/CenTrace).

### 1. Nmap hosts

```
sudo python scripts/nmap_hosts.py <HOST_LIST> <OUTDIR>
```

Requires `sudo`.  This script wraps around `nmap` and parallelizes OS fingerprinting for a list of hosts.
`HOST_LIST` should be the name of a file containing newline-separated IP addresses. `OUTDIR` should be the directory to store each of these results.

### 2. (Optional) Fetch Censys data

```
python scripts/fetch_censys_data.py --filename <HOST_LIST> --outfile <OUT_FILENAME>
```

Requires configuration of `censys-python` library via [`censys config`](https://censys-python.readthedocs.io/en/stable/quick-start.html).
`HOST_LIST` should be the name of a file containing newline-separated IP addresses. `OUT_FILENAME` should be the directory to store each of these results. If `--outfile` is omitted, will write to `stdout`.


### 3. Generate Nmap data summary

```
python scripts/nmap_analysis.py --dir <NMAP_DIR> --censys <CENSYS_FILE> --probes <CENTRACE_CSV> --outfile <OUT_CSV>
```
Summarizes relevant results from Nmap, CenTrace, and Censys into a single CSV. 
`NMAP_DIR` generated from step 1., `CENSYS_FILE` generated from 2., and `CENTRACE_CSV` generated from CenTrace.
`--censys` and `--probes` are optional arguments and can be omitted.
If `--outfile` is omitted, will write to `stdout`.

### 4. Banner grabs using Zgrab.
```
python scripts/prep_zgrab.py --nmap_csv <NMAP_CSV> | zgrab multiple -c zgrab.ini > <ZGRAB_OUT>
```
Requires zgrab CLI tool to be installed. `prep_zgrab.py` can also output to a file instead of `stdout` with `--outfile` argument.

## Clustering

Clustering and analysis are done via Jupyter Notebooks located in `notebooks/`.
These Notebooks expect the data from `CenTrace`, `CenProbe`, and `CenFuzz` aggregated into one large table, joined on the probed IP address. To access the full dataset for this project, please email `ramaks@umich.edu` or `monaw@princeton.edu`.

Run `jupyter notebook`. 

The `cluster` notebook can be run with the resulting `.pkl` file. It then perform various supervised and unsupervised learning tasks with different subsets of the data.


## Disclaimer
Running `CenProbe` scripts from your machine may place you at risk if you use it within a highly censoring regime. `CenProbe` takes actions that try to trigger censoring middleboxes multiple times, and try to interfere with the functioning of the middlebox. Therefore, please exercice caution while using the tool, and understand the risks of running `CenProbe` before using it on your machine. Please refer to [our paper](https://ramakrishnansr.org/publications) for more information. 


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


