# Dockerfile to create a container with the IM client
FROM alpine:3.16
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="1.8.2"
LABEL description="Container image to run the IM client. (http://www.grycap.upv.es/im)"

# Install python3
RUN  apk add --no-cache python3 py3-requests py3-packaging jq bash openssh-client

# Install IM client
RUN  apk add --no-cache py3-pip && \
     pip3 install im-client==1.8.2 && \
     apk del --no-cache py3-pip

COPY im_client.cfg /im-client/im_client.cfg

WORKDIR /im-client

ENTRYPOINT ["/usr/bin/im_client.py"]
