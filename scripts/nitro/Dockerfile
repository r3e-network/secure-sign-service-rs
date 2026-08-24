# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

FROM alpine:3.22 AS crypto
RUN apk add --no-cache openssl

FROM scratch

ARG BIN
ARG WALLET

COPY ${BIN} /bin/secure-sign-service
COPY ${WALLET} /bin/nep6-wallet.json
COPY --from=crypto /usr/bin/openssl /usr/bin/openssl
COPY --from=crypto /lib/ld-musl-*.so.1 /lib/
COPY --from=crypto /usr/lib/libcrypto.so.3 /usr/lib/libcrypto.so.3
COPY --from=crypto /usr/lib/libssl.so.3 /usr/lib/libssl.so.3

CMD ["/bin/secure-sign-service", "run", "--wallet", "/bin/nep6-wallet.json", "--cid", "2345", "--network", "860833102"]
