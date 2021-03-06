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