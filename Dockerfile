FROM jupyter/scipy-notebook

WORKDIR /home/jovyan

ADD requirements.txt /home/jovyan
ADD Pipfile /home/jovyan
ADD Pipfile.lock /home/jovyan

RUN pip install -r requirements.txt
RUN pipenv install --system
