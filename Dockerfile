FROM jupyter/scipy-notebook

WORKDIR /home/jovyan

ADD requirements.txt /home/jovyan
ADD Pipfile /home/jovyan
ADD Pipfile.lock /home/jovyan
ADD apt.txt /home/jovyan

RUN pip install -r requirements.txt
RUN pipenv install --system

USER root
RUN apt update
RUN cat apt.txt | xargs apt install -y
RUN pip install jupyter_contrib_nbextensions && jupyter contrib nbextension install