# Code to our study on discovering IoT deployments in the IPv6 Internet

## Description

This repository contains core code we used to perform our IoT-focused IPv6 Internet measurements. Specifically, we publish code that allows to orchestrate the different address generators and scanning tools.

If you use any portion of our work, please cite our paper:

```bibtex
@inproceedings{2024_dahlmanns_ipv6-deployments,
    author = {Dahlmanns, Markus and Heidenreich, Felix and Lohm{\"o}ller, Johannes and Pennekamp, Jan and Wehrle, Klaus and Henze, Martin},
    title = {{Unconsidered Installations: Discovering IoT Deployments in the IPv6 Internet}},
    booktitle = {Proceedings of the 2024 IEEE/IFIP Network Operations and Management Symposium (NOMS '24), May 6-10, 2024, Seoul, Korea},
    year = {2024},
    publisher = {IEEE},
}
```

## Repository Content

The content of this repository splits into two tools: *ipv6-scanlist-generator* and *scan-tool*.

### ipv6-scanlist-generator

The folder ipv6-scanlist-generator includes our tool that downloads seedlists from different sources, e.g., HTTP servers, orchestrates random IP address selection, and runs passive generators on these sublists.

### scan-tool

The folder scan-tool includes our tool that downloads the generated scanlist, feeds it into ZMAPv6 and runs active generators on sublists.
