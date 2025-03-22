# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

FROM alpine:latest

ARG BIN
ARG WALLET

RUN echo "ARGS: BIN=${BIN}, WALLET=${WALLET}"

COPY ${BIN} /bin/secure-sign-service
COPY ${WALLET} /bin/nep6-wallet.json
RUN chmod +x /bin/secure-sign-service

CMD ["/bin/secure-sign-service", "run", "--wallet", "/bin/nep6-wallet.json", "--cid", "2345"]
