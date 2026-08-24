# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

FROM scratch

ARG BIN
ARG WALLET

COPY ${BIN} /bin/secure-sign-service
COPY ${WALLET} /bin/nep6-wallet.json

CMD ["/bin/secure-sign-service", "run", "--wallet", "/bin/nep6-wallet.json", "--cid", "2345", "--network", "860833102"]
