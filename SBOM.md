# Software Bill of Materials
Generated on: Wed Jun  4 09:19:36 CST 2025

## Direct Dependencies
secure-sign v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign) - MIT
├── aes-gcm v0.10.3 - Apache-2.0 OR MIT
├── clap v4.5.32 - MIT OR Apache-2.0
├── env_logger v0.11.8 - MIT OR Apache-2.0
├── hex v0.4.3 - MIT OR Apache-2.0
├── log v0.4.26 - MIT OR Apache-2.0
├── p256 v0.13.2 - Apache-2.0 OR MIT
├── rpassword v7.3.1 - Apache-2.0
├── secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT
│   [build-dependencies]
├── secure-sign-rpc v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-rpc) - MIT
│   [build-dependencies]
│   [dev-dependencies]
├── serde_json v1.0.140 - MIT OR Apache-2.0
├── tokio v1.44.0 - MIT
├── tonic v0.12.3 - MIT
└── zeroize v1.8.1 - Apache-2.0 OR MIT

secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT (*)

secure-sign-nitro v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-nitro) - MIT
├── aws-nitro-enclaves-nsm-api v0.4.0 - Apache-2.0
├── secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT (*)
├── thiserror v2.0.12 - MIT OR Apache-2.0
└── zeroize v1.8.1 - Apache-2.0 OR MIT (*)

secure-sign-rpc v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-rpc) - MIT (*)

## All Dependencies
secure-sign v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign) - MIT
├── aes-gcm v0.10.3 - Apache-2.0 OR MIT
│   ├── aead v0.5.2 - MIT OR Apache-2.0
│   │   ├── crypto-common v0.1.6 - MIT OR Apache-2.0
│   │   │   ├── generic-array v0.14.7 - MIT
│   │   │   │   ├── typenum v1.18.0 - MIT OR Apache-2.0
│   │   │   │   └── zeroize v1.8.1 - Apache-2.0 OR MIT
│   │   │   │       └── zeroize_derive v1.4.2 (proc-macro) - Apache-2.0 OR MIT
│   │   │   │           ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0
│   │   │   │           │   └── unicode-ident v1.0.18 - (MIT OR Apache-2.0) AND Unicode-3.0
│   │   │   │           ├── quote v1.0.39 - MIT OR Apache-2.0
│   │   │   │           │   └── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │           └── syn v2.0.99 - MIT OR Apache-2.0
│   │   │   │               ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │               ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │               └── unicode-ident v1.0.18 - (MIT OR Apache-2.0) AND Unicode-3.0
│   │   │   │   [build-dependencies]
│   │   │   │   └── version_check v0.9.5 - MIT/Apache-2.0
│   │   │   ├── rand_core v0.6.4 - MIT OR Apache-2.0
│   │   │   │   └── getrandom v0.2.15 - MIT OR Apache-2.0
│   │   │   │       ├── cfg-if v1.0.0 - MIT/Apache-2.0
│   │   │   │       └── libc v0.2.170 - MIT OR Apache-2.0
│   │   │   └── typenum v1.18.0 - MIT OR Apache-2.0
│   │   └── generic-array v0.14.7 - MIT (*)
│   ├── aes v0.8.4 - MIT OR Apache-2.0
│   │   ├── cfg-if v1.0.0 - MIT/Apache-2.0
│   │   ├── cipher v0.4.4 - MIT OR Apache-2.0
│   │   │   ├── crypto-common v0.1.6 - MIT OR Apache-2.0 (*)
│   │   │   └── inout v0.1.4 - MIT OR Apache-2.0
│   │   │       └── generic-array v0.14.7 - MIT (*)
│   │   └── cpufeatures v0.2.17 - MIT OR Apache-2.0
│   │       └── libc v0.2.170 - MIT OR Apache-2.0
│   ├── cipher v0.4.4 - MIT OR Apache-2.0 (*)
│   ├── ctr v0.9.2 - MIT OR Apache-2.0
│   │   └── cipher v0.4.4 - MIT OR Apache-2.0 (*)
│   ├── ghash v0.5.1 - Apache-2.0 OR MIT
│   │   ├── opaque-debug v0.3.1 - MIT OR Apache-2.0
│   │   └── polyval v0.6.2 - Apache-2.0 OR MIT
│   │       ├── cfg-if v1.0.0 - MIT/Apache-2.0
│   │       ├── cpufeatures v0.2.17 - MIT OR Apache-2.0 (*)
│   │       ├── opaque-debug v0.3.1 - MIT OR Apache-2.0
│   │       └── universal-hash v0.5.1 - MIT OR Apache-2.0
│   │           ├── crypto-common v0.1.6 - MIT OR Apache-2.0 (*)
│   │           └── subtle v2.6.1 - BSD-3-Clause
│   └── subtle v2.6.1 - BSD-3-Clause
├── clap v4.5.32 - MIT OR Apache-2.0
│   ├── clap_builder v4.5.32 - MIT OR Apache-2.0
│   │   ├── anstream v0.6.18 - MIT OR Apache-2.0
│   │   │   ├── anstyle v1.0.10 - MIT OR Apache-2.0
│   │   │   ├── anstyle-parse v0.2.6 - MIT OR Apache-2.0
│   │   │   │   └── utf8parse v0.2.2 - Apache-2.0 OR MIT
│   │   │   ├── anstyle-query v1.1.2 - MIT OR Apache-2.0
│   │   │   ├── colorchoice v1.0.3 - MIT OR Apache-2.0
│   │   │   ├── is_terminal_polyfill v1.70.1 - MIT OR Apache-2.0
│   │   │   └── utf8parse v0.2.2 - Apache-2.0 OR MIT
│   │   ├── anstyle v1.0.10 - MIT OR Apache-2.0
│   │   ├── clap_lex v0.7.4 - MIT OR Apache-2.0
│   │   └── strsim v0.11.1 - MIT
│   └── clap_derive v4.5.32 (proc-macro) - MIT OR Apache-2.0
│       ├── heck v0.5.0 - MIT OR Apache-2.0
│       ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│       ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│       └── syn v2.0.99 - MIT OR Apache-2.0 (*)
├── env_logger v0.11.8 - MIT OR Apache-2.0
│   ├── anstream v0.6.18 - MIT OR Apache-2.0 (*)
│   ├── anstyle v1.0.10 - MIT OR Apache-2.0
│   ├── env_filter v0.1.3 - MIT OR Apache-2.0
│   │   ├── log v0.4.26 - MIT OR Apache-2.0
│   │   └── regex v1.11.1 - MIT OR Apache-2.0
│   │       ├── aho-corasick v1.1.3 - Unlicense OR MIT
│   │       │   └── memchr v2.7.4 - Unlicense OR MIT
│   │       ├── memchr v2.7.4 - Unlicense OR MIT
│   │       ├── regex-automata v0.4.9 - MIT OR Apache-2.0
│   │       │   ├── aho-corasick v1.1.3 - Unlicense OR MIT (*)
│   │       │   ├── memchr v2.7.4 - Unlicense OR MIT
│   │       │   └── regex-syntax v0.8.5 - MIT OR Apache-2.0
│   │       └── regex-syntax v0.8.5 - MIT OR Apache-2.0
│   ├── jiff v0.2.10 - Unlicense OR MIT
│   └── log v0.4.26 - MIT OR Apache-2.0
├── hex v0.4.3 - MIT OR Apache-2.0
├── log v0.4.26 - MIT OR Apache-2.0
├── p256 v0.13.2 - Apache-2.0 OR MIT
│   ├── ecdsa v0.16.9 - Apache-2.0 OR MIT
│   │   ├── der v0.7.9 - Apache-2.0 OR MIT
│   │   │   ├── const-oid v0.9.6 - Apache-2.0 OR MIT
│   │   │   └── zeroize v1.8.1 - Apache-2.0 OR MIT (*)
│   │   ├── digest v0.10.7 - MIT OR Apache-2.0
│   │   │   ├── block-buffer v0.10.4 - MIT OR Apache-2.0
│   │   │   │   └── generic-array v0.14.7 - MIT (*)
│   │   │   ├── const-oid v0.9.6 - Apache-2.0 OR MIT
│   │   │   ├── crypto-common v0.1.6 - MIT OR Apache-2.0 (*)
│   │   │   └── subtle v2.6.1 - BSD-3-Clause
│   │   ├── elliptic-curve v0.13.8 - Apache-2.0 OR MIT
│   │   │   ├── base16ct v0.2.0 - Apache-2.0 OR MIT
│   │   │   ├── crypto-bigint v0.5.5 - Apache-2.0 OR MIT
│   │   │   │   ├── generic-array v0.14.7 - MIT (*)
│   │   │   │   ├── rand_core v0.6.4 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── subtle v2.6.1 - BSD-3-Clause
│   │   │   │   └── zeroize v1.8.1 - Apache-2.0 OR MIT (*)
│   │   │   ├── digest v0.10.7 - MIT OR Apache-2.0 (*)
│   │   │   ├── ff v0.13.1 - MIT/Apache-2.0
│   │   │   │   ├── rand_core v0.6.4 - MIT OR Apache-2.0 (*)
│   │   │   │   └── subtle v2.6.1 - BSD-3-Clause
│   │   │   ├── generic-array v0.14.7 - MIT (*)
│   │   │   ├── group v0.13.0 - MIT/Apache-2.0
│   │   │   │   ├── ff v0.13.1 - MIT/Apache-2.0 (*)
│   │   │   │   ├── rand_core v0.6.4 - MIT OR Apache-2.0 (*)
│   │   │   │   └── subtle v2.6.1 - BSD-3-Clause
│   │   │   ├── hkdf v0.12.4 - MIT OR Apache-2.0
│   │   │   │   └── hmac v0.12.1 - MIT OR Apache-2.0
│   │   │   │       └── digest v0.10.7 - MIT OR Apache-2.0 (*)
│   │   │   ├── rand_core v0.6.4 - MIT OR Apache-2.0 (*)
│   │   │   ├── sec1 v0.7.3 - Apache-2.0 OR MIT
│   │   │   │   ├── base16ct v0.2.0 - Apache-2.0 OR MIT
│   │   │   │   ├── der v0.7.9 - Apache-2.0 OR MIT (*)
│   │   │   │   ├── generic-array v0.14.7 - MIT (*)
│   │   │   │   ├── subtle v2.6.1 - BSD-3-Clause
│   │   │   │   └── zeroize v1.8.1 - Apache-2.0 OR MIT (*)
│   │   │   ├── subtle v2.6.1 - BSD-3-Clause
│   │   │   └── zeroize v1.8.1 - Apache-2.0 OR MIT (*)
│   │   ├── rfc6979 v0.4.0 - Apache-2.0 OR MIT
│   │   │   ├── hmac v0.12.1 - MIT OR Apache-2.0 (*)
│   │   │   └── subtle v2.6.1 - BSD-3-Clause
│   │   └── signature v2.2.0 - Apache-2.0 OR MIT
│   │       ├── digest v0.10.7 - MIT OR Apache-2.0 (*)
│   │       └── rand_core v0.6.4 - MIT OR Apache-2.0 (*)
│   ├── elliptic-curve v0.13.8 - Apache-2.0 OR MIT (*)
│   ├── primeorder v0.13.6 - Apache-2.0 OR MIT
│   │   └── elliptic-curve v0.13.8 - Apache-2.0 OR MIT (*)
│   └── sha2 v0.10.8 - MIT OR Apache-2.0
│       ├── cfg-if v1.0.0 - MIT/Apache-2.0
│       ├── cpufeatures v0.2.17 - MIT OR Apache-2.0 (*)
│       ├── digest v0.10.7 - MIT OR Apache-2.0 (*)
│       └── sha2-asm v0.6.4 - MIT
│           [build-dependencies]
│           └── cc v1.2.16 - MIT OR Apache-2.0
│               └── shlex v1.3.0 - MIT OR Apache-2.0
├── rpassword v7.3.1 - Apache-2.0
│   ├── libc v0.2.170 - MIT OR Apache-2.0
│   └── rtoolbox v0.0.2 - Apache-2.0
│       └── libc v0.2.170 - MIT OR Apache-2.0
├── secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT
│   ├── aes v0.8.4 - MIT OR Apache-2.0 (*)
│   ├── base58 v0.2.0 - MIT
│   ├── base64 v0.22.1 - MIT OR Apache-2.0
│   ├── bytes v1.10.1 - MIT
│   ├── getrandom v0.3.1 - MIT OR Apache-2.0
│   │   ├── cfg-if v1.0.0 - MIT/Apache-2.0
│   │   └── libc v0.2.170 - MIT OR Apache-2.0
│   ├── hashbrown v0.15.2 - MIT OR Apache-2.0
│   │   ├── allocator-api2 v0.2.21 - MIT OR Apache-2.0
│   │   ├── equivalent v1.0.2 - Apache-2.0 OR MIT
│   │   └── foldhash v0.1.5 - Zlib
│   ├── hex v0.4.3 - MIT OR Apache-2.0
│   ├── hmac v0.12.1 - MIT OR Apache-2.0 (*)
│   ├── p256 v0.13.2 - Apache-2.0 OR MIT (*)
│   ├── prost v0.13.5 - Apache-2.0
│   │   ├── bytes v1.10.1 - MIT
│   │   └── prost-derive v0.13.5 (proc-macro) - Apache-2.0
│   │       ├── anyhow v1.0.95 - MIT OR Apache-2.0
│   │       ├── itertools v0.13.0 - MIT OR Apache-2.0
│   │       │   └── either v1.13.0 - MIT OR Apache-2.0
│   │       ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │       ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │       └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   ├── prost-types v0.13.5 - Apache-2.0
│   │   └── prost v0.13.5 - Apache-2.0 (*)
│   ├── ripemd v0.1.3 - MIT OR Apache-2.0
│   │   └── digest v0.10.7 - MIT OR Apache-2.0 (*)
│   ├── scrypt v0.2.0 - MIT OR Apache-2.0
│   │   ├── byte-tools v0.3.1 - MIT OR Apache-2.0
│   │   ├── byteorder v1.5.0 - Unlicense OR MIT
│   │   ├── hmac v0.7.1 - MIT OR Apache-2.0
│   │   │   ├── crypto-mac v0.7.0 - MIT OR Apache-2.0
│   │   │   │   ├── generic-array v0.12.4 - MIT
│   │   │   │   │   └── typenum v1.18.0 - MIT OR Apache-2.0
│   │   │   │   └── subtle v1.0.0 - BSD-3-Clause
│   │   │   └── digest v0.8.1 - MIT OR Apache-2.0
│   │   │       └── generic-array v0.12.4 - MIT (*)
│   │   ├── pbkdf2 v0.3.0 - MIT OR Apache-2.0
│   │   │   ├── byteorder v1.5.0 - Unlicense OR MIT
│   │   │   └── crypto-mac v0.7.0 - MIT OR Apache-2.0 (*)
│   │   └── sha2 v0.8.2 - MIT OR Apache-2.0
│   │       ├── block-buffer v0.7.3 - MIT OR Apache-2.0
│   │       │   ├── block-padding v0.1.5 - MIT OR Apache-2.0
│   │       │   │   └── byte-tools v0.3.1 - MIT OR Apache-2.0
│   │       │   ├── byte-tools v0.3.1 - MIT OR Apache-2.0
│   │       │   ├── byteorder v1.5.0 - Unlicense OR MIT
│   │       │   └── generic-array v0.12.4 - MIT (*)
│   │       ├── digest v0.8.1 - MIT OR Apache-2.0 (*)
│   │       ├── fake-simd v0.1.2 - MIT/Apache-2.0
│   │       └── opaque-debug v0.2.3 - MIT OR Apache-2.0
│   ├── serde v1.0.218 - MIT OR Apache-2.0
│   │   └── serde_derive v1.0.218 (proc-macro) - MIT OR Apache-2.0
│   │       ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │       ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │       └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   ├── serde_json v1.0.140 - MIT OR Apache-2.0
│   │   ├── itoa v1.0.15 - MIT OR Apache-2.0
│   │   ├── memchr v2.7.4 - Unlicense OR MIT
│   │   ├── ryu v1.0.20 - Apache-2.0 OR BSL-1.0
│   │   └── serde v1.0.218 - MIT OR Apache-2.0 (*)
│   ├── sha2 v0.10.8 - MIT OR Apache-2.0 (*)
│   ├── subtle v2.6.1 - BSD-3-Clause
│   ├── thiserror v2.0.12 - MIT OR Apache-2.0
│   │   └── thiserror-impl v2.0.12 (proc-macro) - MIT OR Apache-2.0
│   │       ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │       ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │       └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   └── zeroize v1.8.1 - Apache-2.0 OR MIT (*)
│   [build-dependencies]
│   └── prost-build v0.13.5 - Apache-2.0
│       ├── heck v0.5.0 - MIT OR Apache-2.0
│       ├── itertools v0.13.0 - MIT OR Apache-2.0 (*)
│       ├── log v0.4.26 - MIT OR Apache-2.0
│       ├── multimap v0.10.0 - MIT OR Apache-2.0
│       ├── once_cell v1.20.3 - MIT OR Apache-2.0
│       ├── petgraph v0.7.1 - MIT OR Apache-2.0
│       │   ├── fixedbitset v0.5.7 - MIT OR Apache-2.0
│       │   └── indexmap v2.7.1 - Apache-2.0 OR MIT
│       │       ├── equivalent v1.0.2 - Apache-2.0 OR MIT
│       │       └── hashbrown v0.15.2 - MIT OR Apache-2.0 (*)
│       ├── prettyplease v0.2.30 - MIT OR Apache-2.0
│       │   ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│       │   └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│       ├── prost v0.13.5 - Apache-2.0 (*)
│       ├── prost-types v0.13.5 - Apache-2.0
│       │   └── prost v0.13.5 - Apache-2.0 (*)
│       ├── regex v1.11.1 - MIT OR Apache-2.0
│       │   ├── regex-automata v0.4.9 - MIT OR Apache-2.0
│       │   │   └── regex-syntax v0.8.5 - MIT OR Apache-2.0
│       │   └── regex-syntax v0.8.5 - MIT OR Apache-2.0
│       ├── syn v2.0.99 - MIT OR Apache-2.0 (*)
│       └── tempfile v3.18.0 - MIT OR Apache-2.0
│           ├── cfg-if v1.0.0 - MIT/Apache-2.0
│           ├── fastrand v2.3.0 - Apache-2.0 OR MIT
│           ├── getrandom v0.3.1 - MIT OR Apache-2.0 (*)
│           ├── once_cell v1.20.3 - MIT OR Apache-2.0
│           └── rustix v1.0.1 - Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT
│               ├── bitflags v2.9.0 - MIT OR Apache-2.0
│               ├── errno v0.3.10 - MIT OR Apache-2.0
│               │   └── libc v0.2.170 - MIT OR Apache-2.0
│               └── libc v0.2.170 - MIT OR Apache-2.0
├── secure-sign-rpc v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-rpc) - MIT
│   ├── aes-gcm v0.10.3 - Apache-2.0 OR MIT (*)
│   ├── hex v0.4.3 - MIT OR Apache-2.0
│   ├── hyper-util v0.1.10 - MIT
│   │   ├── bytes v1.10.1 - MIT
│   │   ├── futures-channel v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   └── futures-sink v0.3.31 - MIT OR Apache-2.0
│   │   ├── futures-util v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-channel v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-io v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-macro v0.3.31 (proc-macro) - MIT OR Apache-2.0
│   │   │   │   ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │   └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   │   │   ├── futures-sink v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-task v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── memchr v2.7.4 - Unlicense OR MIT
│   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   ├── pin-utils v0.1.0 - MIT OR Apache-2.0
│   │   │   └── slab v0.4.9 - MIT
│   │   │       [build-dependencies]
│   │   │       └── autocfg v1.4.0 - Apache-2.0 OR MIT
│   │   ├── http v1.2.0 - MIT OR Apache-2.0
│   │   │   ├── bytes v1.10.1 - MIT
│   │   │   ├── fnv v1.0.7 - Apache-2.0 / MIT
│   │   │   └── itoa v1.0.15 - MIT OR Apache-2.0
│   │   ├── http-body v1.0.1 - MIT
│   │   │   ├── bytes v1.10.1 - MIT
│   │   │   └── http v1.2.0 - MIT OR Apache-2.0 (*)
│   │   ├── hyper v1.6.0 - MIT
│   │   │   ├── bytes v1.10.1 - MIT
│   │   │   ├── futures-channel v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   ├── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   ├── h2 v0.4.8 - MIT
│   │   │   │   ├── atomic-waker v1.1.2 - Apache-2.0 OR MIT
│   │   │   │   ├── bytes v1.10.1 - MIT
│   │   │   │   ├── fnv v1.0.7 - Apache-2.0 / MIT
│   │   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   │   ├── futures-sink v0.3.31 - MIT OR Apache-2.0
│   │   │   │   ├── http v1.2.0 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── indexmap v2.7.1 - Apache-2.0 OR MIT (*)
│   │   │   │   ├── slab v0.4.9 - MIT (*)
│   │   │   │   ├── tokio v1.44.0 - MIT
│   │   │   │   │   ├── bytes v1.10.1 - MIT
│   │   │   │   │   ├── libc v0.2.170 - MIT OR Apache-2.0
│   │   │   │   │   ├── mio v1.0.3 - MIT
│   │   │   │   │   │   └── libc v0.2.170 - MIT OR Apache-2.0
│   │   │   │   │   ├── parking_lot v0.12.3 - MIT OR Apache-2.0
│   │   │   │   │   │   ├── lock_api v0.4.12 - MIT OR Apache-2.0
│   │   │   │   │   │   │   └── scopeguard v1.2.0 - MIT OR Apache-2.0
│   │   │   │   │   │   │   [build-dependencies]
│   │   │   │   │   │   │   └── autocfg v1.4.0 - Apache-2.0 OR MIT
│   │   │   │   │   │   └── parking_lot_core v0.9.10 - MIT OR Apache-2.0
│   │   │   │   │   │       ├── cfg-if v1.0.0 - MIT/Apache-2.0
│   │   │   │   │   │       ├── libc v0.2.170 - MIT OR Apache-2.0
│   │   │   │   │   │       └── smallvec v1.14.0 - MIT OR Apache-2.0
│   │   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   │   ├── signal-hook-registry v1.4.2 - Apache-2.0/MIT
│   │   │   │   │   │   └── libc v0.2.170 - MIT OR Apache-2.0
│   │   │   │   │   ├── socket2 v0.5.8 - MIT OR Apache-2.0
│   │   │   │   │   │   └── libc v0.2.170 - MIT OR Apache-2.0
│   │   │   │   │   └── tokio-macros v2.5.0 (proc-macro) - MIT
│   │   │   │   │       ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │   │       ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │   │       └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── tokio-util v0.7.13 - MIT
│   │   │   │   │   ├── bytes v1.10.1 - MIT
│   │   │   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   │   │   ├── futures-sink v0.3.31 - MIT OR Apache-2.0
│   │   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   │   └── tokio v1.44.0 - MIT (*)
│   │   │   │   └── tracing v0.1.41 - MIT
│   │   │   │       ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │       ├── tracing-attributes v0.1.28 (proc-macro) - MIT
│   │   │   │       │   ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │       │   ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │       │   └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   │   │   │       └── tracing-core v0.1.33 - MIT
│   │   │   │           └── once_cell v1.20.3 - MIT OR Apache-2.0
│   │   │   ├── http v1.2.0 - MIT OR Apache-2.0 (*)
│   │   │   ├── http-body v1.0.1 - MIT (*)
│   │   │   ├── httparse v1.10.1 - MIT OR Apache-2.0
│   │   │   ├── httpdate v1.0.3 - MIT OR Apache-2.0
│   │   │   ├── itoa v1.0.15 - MIT OR Apache-2.0
│   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   ├── smallvec v1.14.0 - MIT OR Apache-2.0
│   │   │   ├── tokio v1.44.0 - MIT (*)
│   │   │   └── want v0.3.1 - MIT
│   │   │       └── try-lock v0.2.5 - MIT
│   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   ├── socket2 v0.5.8 - MIT OR Apache-2.0 (*)
│   │   ├── tokio v1.44.0 - MIT (*)
│   │   ├── tower-service v0.3.3 - MIT
│   │   └── tracing v0.1.41 - MIT (*)
│   ├── p256 v0.13.2 - Apache-2.0 OR MIT (*)
│   ├── prost v0.13.5 - Apache-2.0 (*)
│   ├── secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT (*)
│   ├── tokio v1.44.0 - MIT (*)
│   ├── tokio-vsock v0.7.0 - Apache-2.0
│   │   ├── bytes v1.10.1 - MIT
│   │   ├── futures v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-channel v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-executor v0.3.31 - MIT OR Apache-2.0
│   │   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   │   ├── futures-task v0.3.31 - MIT OR Apache-2.0
│   │   │   │   └── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   ├── futures-io v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-sink v0.3.31 - MIT OR Apache-2.0
│   │   │   ├── futures-task v0.3.31 - MIT OR Apache-2.0
│   │   │   └── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   ├── libc v0.2.170 - MIT OR Apache-2.0
│   │   ├── tokio v1.44.0 - MIT (*)
│   │   ├── tonic v0.12.3 - MIT
│   │   │   ├── async-stream v0.3.6 - MIT
│   │   │   │   ├── async-stream-impl v0.3.6 (proc-macro) - MIT
│   │   │   │   │   ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │   │   ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │   │   └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   │   └── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   ├── async-trait v0.1.87 (proc-macro) - MIT OR Apache-2.0
│   │   │   │   ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │   └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   │   │   ├── axum v0.7.9 - MIT
│   │   │   │   ├── async-trait v0.1.87 (proc-macro) - MIT OR Apache-2.0 (*)
│   │   │   │   ├── axum-core v0.4.5 - MIT
│   │   │   │   │   ├── async-trait v0.1.87 (proc-macro) - MIT OR Apache-2.0 (*)
│   │   │   │   │   ├── bytes v1.10.1 - MIT
│   │   │   │   │   ├── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   │   │   ├── http v1.2.0 - MIT OR Apache-2.0 (*)
│   │   │   │   │   ├── http-body v1.0.1 - MIT (*)
│   │   │   │   │   ├── http-body-util v0.1.2 - MIT
│   │   │   │   │   │   ├── bytes v1.10.1 - MIT
│   │   │   │   │   │   ├── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   │   │   │   ├── http v1.2.0 - MIT OR Apache-2.0 (*)
│   │   │   │   │   │   ├── http-body v1.0.1 - MIT (*)
│   │   │   │   │   │   └── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   │   ├── mime v0.3.17 - MIT OR Apache-2.0
│   │   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   │   ├── rustversion v1.0.20 (proc-macro) - MIT OR Apache-2.0
│   │   │   │   │   ├── sync_wrapper v1.0.2 - Apache-2.0
│   │   │   │   │   ├── tower-layer v0.3.3 - MIT
│   │   │   │   │   └── tower-service v0.3.3 - MIT
│   │   │   │   ├── bytes v1.10.1 - MIT
│   │   │   │   ├── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── http v1.2.0 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── http-body v1.0.1 - MIT (*)
│   │   │   │   ├── http-body-util v0.1.2 - MIT (*)
│   │   │   │   ├── itoa v1.0.15 - MIT OR Apache-2.0
│   │   │   │   ├── matchit v0.7.3 - MIT AND BSD-3-Clause
│   │   │   │   ├── memchr v2.7.4 - Unlicense OR MIT
│   │   │   │   ├── mime v0.3.17 - MIT OR Apache-2.0
│   │   │   │   ├── percent-encoding v2.3.1 - MIT OR Apache-2.0
│   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   ├── rustversion v1.0.20 (proc-macro) - MIT OR Apache-2.0
│   │   │   │   ├── serde v1.0.218 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── sync_wrapper v1.0.2 - Apache-2.0
│   │   │   │   ├── tower v0.5.2 - MIT
│   │   │   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   │   │   ├── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   │   ├── sync_wrapper v1.0.2 - Apache-2.0
│   │   │   │   │   ├── tower-layer v0.3.3 - MIT
│   │   │   │   │   └── tower-service v0.3.3 - MIT
│   │   │   │   ├── tower-layer v0.3.3 - MIT
│   │   │   │   └── tower-service v0.3.3 - MIT
│   │   │   ├── base64 v0.22.1 - MIT OR Apache-2.0
│   │   │   ├── bytes v1.10.1 - MIT
│   │   │   ├── h2 v0.4.8 - MIT (*)
│   │   │   ├── http v1.2.0 - MIT OR Apache-2.0 (*)
│   │   │   ├── http-body v1.0.1 - MIT (*)
│   │   │   ├── http-body-util v0.1.2 - MIT (*)
│   │   │   ├── hyper v1.6.0 - MIT (*)
│   │   │   ├── hyper-timeout v0.5.2 - MIT OR Apache-2.0
│   │   │   │   ├── hyper v1.6.0 - MIT (*)
│   │   │   │   ├── hyper-util v0.1.10 - MIT (*)
│   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   ├── tokio v1.44.0 - MIT (*)
│   │   │   │   └── tower-service v0.3.3 - MIT
│   │   │   ├── hyper-util v0.1.10 - MIT (*)
│   │   │   ├── percent-encoding v2.3.1 - MIT OR Apache-2.0
│   │   │   ├── pin-project v1.1.10 - Apache-2.0 OR MIT
│   │   │   │   └── pin-project-internal v1.1.10 (proc-macro) - Apache-2.0 OR MIT
│   │   │   │       ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │       ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │       └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   │   │   ├── prost v0.13.5 - Apache-2.0 (*)
│   │   │   ├── socket2 v0.5.8 - MIT OR Apache-2.0 (*)
│   │   │   ├── tokio v1.44.0 - MIT (*)
│   │   │   ├── tokio-stream v0.1.17 - MIT
│   │   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   └── tokio v1.44.0 - MIT (*)
│   │   │   ├── tower v0.4.13 - MIT
│   │   │   │   ├── futures-core v0.3.31 - MIT OR Apache-2.0
│   │   │   │   ├── futures-util v0.3.31 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── indexmap v1.9.3 - Apache-2.0 OR MIT
│   │   │   │   │   └── hashbrown v0.12.3 - MIT OR Apache-2.0
│   │   │   │   │   [build-dependencies]
│   │   │   │   │   └── autocfg v1.4.0 - Apache-2.0 OR MIT
│   │   │   │   ├── pin-project v1.1.10 - Apache-2.0 OR MIT (*)
│   │   │   │   ├── pin-project-lite v0.2.16 - Apache-2.0 OR MIT
│   │   │   │   ├── rand v0.8.5 - MIT OR Apache-2.0
│   │   │   │   │   ├── libc v0.2.170 - MIT OR Apache-2.0
│   │   │   │   │   ├── rand_chacha v0.3.1 - MIT OR Apache-2.0
│   │   │   │   │   │   ├── ppv-lite86 v0.2.20 - MIT/Apache-2.0
│   │   │   │   │   │   │   └── zerocopy v0.7.35 - BSD-2-Clause OR Apache-2.0 OR MIT
│   │   │   │   │   │   │       ├── byteorder v1.5.0 - Unlicense OR MIT
│   │   │   │   │   │   │       └── zerocopy-derive v0.7.35 (proc-macro) - BSD-2-Clause OR Apache-2.0 OR MIT
│   │   │   │   │   │   │           ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│   │   │   │   │   │   │           ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│   │   │   │   │   │   │           └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   │   │   │   │   │   └── rand_core v0.6.4 - MIT OR Apache-2.0 (*)
│   │   │   │   │   └── rand_core v0.6.4 - MIT OR Apache-2.0 (*)
│   │   │   │   ├── slab v0.4.9 - MIT (*)
│   │   │   │   ├── tokio v1.44.0 - MIT (*)
│   │   │   │   ├── tokio-util v0.7.13 - MIT (*)
│   │   │   │   ├── tower-layer v0.3.3 - MIT
│   │   │   │   ├── tower-service v0.3.3 - MIT
│   │   │   │   └── tracing v0.1.41 - MIT (*)
│   │   │   ├── tower-layer v0.3.3 - MIT
│   │   │   ├── tower-service v0.3.3 - MIT
│   │   │   └── tracing v0.1.41 - MIT (*)
│   │   └── vsock v0.5.1 - Apache-2.0
│   │       ├── libc v0.2.170 - MIT OR Apache-2.0
│   │       └── nix v0.29.0 - MIT
│   │           ├── bitflags v2.9.0 - MIT OR Apache-2.0
│   │           ├── cfg-if v1.0.0 - MIT/Apache-2.0
│   │           ├── libc v0.2.170 - MIT OR Apache-2.0
│   │           └── memoffset v0.9.1 - MIT
│   │               [build-dependencies]
│   │               └── autocfg v1.4.0 - Apache-2.0 OR MIT
│   │           [build-dependencies]
│   │           └── cfg_aliases v0.2.1 - MIT
│   ├── tonic v0.12.3 - MIT (*)
│   ├── tower v0.5.2 - MIT (*)
│   └── zeroize v1.8.1 - Apache-2.0 OR MIT (*)
│   [build-dependencies]
│   ├── prost-build v0.13.5 - Apache-2.0 (*)
│   ├── secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT (*)
│   └── tonic-build v0.12.3 - MIT
│       ├── prettyplease v0.2.30 - MIT OR Apache-2.0 (*)
│       ├── proc-macro2 v1.0.94 - MIT OR Apache-2.0 (*)
│       ├── prost-build v0.13.5 - Apache-2.0 (*)
│       ├── prost-types v0.13.5 - Apache-2.0 (*)
│       ├── quote v1.0.39 - MIT OR Apache-2.0 (*)
│       └── syn v2.0.99 - MIT OR Apache-2.0 (*)
│   [dev-dependencies]
│   └── tokio v1.44.0 - MIT (*)
├── serde_json v1.0.140 - MIT OR Apache-2.0 (*)
├── tokio v1.44.0 - MIT (*)
├── tonic v0.12.3 - MIT (*)
└── zeroize v1.8.1 - Apache-2.0 OR MIT (*)

secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT (*)

secure-sign-nitro v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-nitro) - MIT
├── aws-nitro-enclaves-nsm-api v0.4.0 - Apache-2.0
│   ├── libc v0.2.170 - MIT OR Apache-2.0
│   ├── log v0.4.26 - MIT OR Apache-2.0
│   ├── nix v0.26.4 - MIT
│   │   ├── bitflags v1.3.2 - MIT/Apache-2.0
│   │   ├── cfg-if v1.0.0 - MIT/Apache-2.0
│   │   ├── libc v0.2.170 - MIT OR Apache-2.0
│   │   ├── memoffset v0.7.1 - MIT
│   │   │   [build-dependencies]
│   │   │   └── autocfg v1.4.0 - Apache-2.0 OR MIT
│   │   └── pin-utils v0.1.0 - MIT OR Apache-2.0
│   ├── serde v1.0.218 - MIT OR Apache-2.0 (*)
│   ├── serde_bytes v0.11.17 - MIT OR Apache-2.0
│   │   └── serde v1.0.218 - MIT OR Apache-2.0 (*)
│   └── serde_cbor v0.11.2 - MIT/Apache-2.0
│       ├── half v1.8.3 - MIT OR Apache-2.0
│       └── serde v1.0.218 - MIT OR Apache-2.0 (*)
├── secure-sign-core v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-core) - MIT (*)
├── thiserror v2.0.12 - MIT OR Apache-2.0 (*)
└── zeroize v1.8.1 - Apache-2.0 OR MIT (*)

secure-sign-rpc v0.1.0 (/Users/jinghuiliao/git/secure-sign-service-rs/secure-sign-rpc) - MIT (*)
