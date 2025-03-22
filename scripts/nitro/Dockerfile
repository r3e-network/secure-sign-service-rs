# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

ARG BIN
ARG WALLET

FROM alpine:latest
COPY $BIN /bin/$BIN
COPY $WALLET /root/$WALLET
RUN chmod +x /bin/$BIN

CMD ["/bin/$BIN", "run", "--wallet", "/root/$WALLET"]
