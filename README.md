# Jupyter Notebooks

This repo contains a collection of Jupyter notebooks focused on infosec and anything else which may be interesting to me.

## Starting

### Docker

```
docker run -d -it $(pwd):/home/jovyan -p 8888:8888 jupyter/scipy-notebook
```

## Collection

### Beacon Analysis

This notebook is designed to be provided with a Cobalt Strike beacon payload, and it will output the embedded configuration.

