FROM python:3.9-alpine

# add non-root user
ARG USERNAME=user
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN addgroup -g $USER_GID $USERNAME
RUN adduser --disabled-password --gecos "" --home /python-docker --no-create-home --ingroup $USERNAME --uid $USER_UID $USERNAME

WORKDIR /python-docker

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY ./app.py .
COPY ./index.html .
COPY ./flag.txt /flag.txt

USER $USERNAME

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=3817"]