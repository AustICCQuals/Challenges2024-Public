FROM openjdk:8-jdk-alpine

# add non-root user
ARG USERNAME=user
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN addgroup -g $USER_GID $USERNAME
RUN adduser --disabled-password --gecos "" --home /app --no-create-home --ingroup $USERNAME --uid $USER_UID $USERNAME

COPY ./sparky.jar /app/app.jar
COPY ./app/index.html /app/index.html
COPY ./app/flag.txt /flag.txt
ENV API_KEY=hKVKgtfNLD4NFxB3LJhLZSVhbeUbsUTW

# run as non-root user
USER $USERNAME

ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app/app.jar"]
