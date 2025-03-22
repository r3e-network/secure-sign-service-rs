// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

fn main() {
    let sdk = std::env::var("SGX_SDK").unwrap_or_else(|_| "/opt/sgxsdk".into());
    println!("cargo:rustc-link-search=native={}/lib64", sdk);
    if std::env::var("SGX_MODE").unwrap_or("SW".into()) == "HW" {
        println!("cargo:rustc-link-lib=sgx_urts");
    } else {
        println!("cargo:rustc-link-lib=sgx_urts_sim");
    }

    println!("cargo:rustc-link-search=native=../secure-sign-sgx-enclave");
    println!("cargo:rustc-link-lib=static=secure_sign_sgx_enclave_untrusted");
}
