# Copyright @ 2025 - Present, R3E Network
# All Rights Reserved

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SIGN_KEY ?= sgx_sign_private_key.pem

# Only include SGX SDK environment when building sgx target
ifeq ($(filter sgx,$(MAKECMDGOALS)),sgx)
    include $(SGX_SDK)/buildenv.mk
endif

SGX_COMMON_FLAGS := -m64
SGX_LIB_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), true)
    SGX_COMMON_FLAGS += -O0 -g
	SGX_CONFIG ?= Enclave.config.xml
else
    SGX_COMMON_FLAGS += -O2
	SGX_CONFIG ?= Enclave.config.production.xml
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

ifneq ($(SGX_MODE), HW)
	SGX_TRTS_LIB := sgx_trts_sim
	SGX_SERVICE_LIB := sgx_tservice_sim
	SGX_URTS_LIB := sgx_urts_sim
else
	SGX_TRTS_LIB := sgx_trts
	SGX_SERVICE_LIB := sgx_tservice
	SGX_URTS_LIB := sgx_urts
endif


ENCLAVE_INCLUDE_PATHS := -I. -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
ENCLAVE_CFLAGS := $(ENCLAVE_INCLUDE_PATHS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections \
	-fdata-sections -fstack-protector-strong $(MITIGATION_CFLAGS)

RUST_LINK_FLAGS := -L./target/x86_64-unknown-linux-gnu/release -lsecure_sign_sgx_enclave
ENCLAVE_SECURITY_LINK_FLAGS := -Wl,-z,relro,-z,now,-z,noexecstack
ENCLAVE_LINK_FLAGS := $(MITIGATION_LDFLAGS) $(ENCLAVE_SECURITY_LINK_FLAGS) -flto \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(SGX_TRTS_LIB) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(SGX_SERVICE_LIB) $(RUST_LINK_FLAGS) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=enclave.lds


.PHONY: debug

debug:
	cargo build --no-default-features

release:
	cargo build --release --no-default-features

SGX_RUST_FLAGS := -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort
SGX_RUST_OPTIONS := --release --no-default-features --target x86_64-unknown-linux-gnu
sgx:
	RUSTFLAGS="--cfg getrandom_backend=\"rdrand\"" cargo +nightly $(SGX_RUST_FLAGS) build $(SGX_RUST_OPTIONS)
	$(SGX_EDGER8R) --trusted enclave.edl --search-path $(SGX_SDK)/include
	$(SGX_EDGER8R) --untrusted enclave.edl --search-path $(SGX_SDK)/include
	$(CC) $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) -c enclave_t.c -o enclave_t.o
	$(CXX) enclave_t.o -o secure_sign_sgx_enclave.so $(ENCLAVE_LINK_FLAGS)
	$(SGX_ENCLAVE_SIGNER) sign -key $(SIGN_KEY) -enclave secure_sign_sgx_enclave.so -out secure_sign_sgx_enclave.signed.so -config $(SGX_CONFIG)
	$(CC) $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -I. -I$(SGX_SDK)/include -c enclave_u.c -o enclave_u.o
	$(AR) rcsD libsecure_sign_sgx_enclave_untrusted.a enclave_u.o

clean:
	rm -f secure_sign_sgx_enclave.so secure_sign_sgx_enclave.signed.so enclave_t.* enclave_u.* libsecure_sign_sgx_enclave_untrusted.a
	cargo clean
