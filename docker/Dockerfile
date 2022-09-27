# Dockerfile to create a container with the IM client
FROM alpine:3.16
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="1.5.11"
LABEL description="Container image to run the IM client. (http://www.grycap.upv.es/im)"

# Install python3
RUN  apk add --no-cache python3 py3-requests jq bash

# Install IM client
RUN  apk add --no-cache py3-pip  && \
     pip3 install https://github.com/grycap/im-client/archive/refs/heads/master.zip && \
     apk del --no-cache py3-pip

ENTRYPOINT ["/usr/bin/im_client.py"]
