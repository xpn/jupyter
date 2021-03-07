# Jupyter Notebooks

This repo contains a collection of Jupyter notebooks focused on infosec and anything else which may be interesting to me.

## Starting

### Docker

```
docker run -it -v $(pwd):/home/jovyan -p 8888:8888 jupyter/scipy-notebook
```

### Binder

This repo has been set up to be launched via Binder. A list of notebooks supported can be found below.

## Collection

### Beacon Analysis

This notebook is designed to be provided with a Cobalt Strike beacon payload, and it will output the embedded configuration.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2Fbeacon_analysis.ipynb)

### VT VBA Analysis

This notebook is used to download a list of samples from VirusTotal, and using OleTools, extract the embedded VBA src from each.

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/xpn/jupyter/HEAD?filepath=notebooks%2Fvirustotal_vba_analysis.ipynb)