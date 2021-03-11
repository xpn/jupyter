# Jupyter Notebooks

This repo contains a collection of Jupyter notebooks focused on infosec and anything else which may be interesting to me.

## Starting

### Docker

As this repo will use a bunch of pips, I've added a `Dockerfile` to make running the notebooks a bit easier. To build this yourself:

```
git clone https://github.com/xpn/jupyter.git jupyter; cd jupyter
docker build . -t xpn/jupyter
docker run -it -v $(pwd):/home/jovyan -p 8888:8888 xpn/jupyter
```

Alternatively, there is a pre-built image which you can grab using:

```
git clone https://github.com/xpn/jupyter.git jupyter; cd jupyter
docker pull docker.pkg.github.com/xpn/jupyter/jupyter:latest
docker run -it -v $(pwd):/home/jovyan -p 8888:8888 docker.pkg.github.com/xpn/jupyter/jupyter:latest
```

### Binder

This repo has been set up to be launched via Binder. A list of notebooks supported can be found below.

## Collection

### Beacon Analysis

This notebook is designed to be provided with a Cobalt Strike beacon payload, and it will output the embedded configuration.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2Fbeacon_analysis.ipynb)

### Beacon Stager Emulation

This notebook takes a Cobalt Strike stager and using FireEye Speakeasy, emulates the payload execution to recover the `beacon.bin` download path, host and port.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2Fbeacon_stager_analysis.ipynb)

### VT VBA Analysis

This notebook is used to download a list of samples from VirusTotal, and using OleTools, extract the embedded VBA src from each.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2Fvirustotal_vba_analysis.ipynb)

### Yara Playground

This notebook takes prevous samples (for example, from VT VBA Analysis) and allows us to play around with running/crafting Yara rules to match.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2Fyara_playground.ipynb)

### HAFNIUM WebShell

Using the Microsoft MSTIC feed, this notebook retrieves IOCs, downloads samples from VirusTotal and presents them for further review.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2FHAFNIUM_WebShells.ipynb)

### HAFNIUM WebShell VT Search

Using common strings seen in the MSTIC feed, we can retrieve further examples of HAFNIUM webshells for analysis using this notebook.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2FHAFNIUM_WebShells_VT_Search.ipynb)