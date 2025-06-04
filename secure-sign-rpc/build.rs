// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::fs;
use std::io::Result;

fn main() -> Result<()> {
    // Ensure output directory exists
    fs::create_dir_all("src/")?;

    tonic_build::configure()
        .out_dir("src/")
        // .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .extern_path(".signpb", "::secure_sign_core::neo::signpb")
        .compile_protos(
            &["proto/servicepb.proto", "proto/startpb.proto"],
            &["proto/", "../secure-sign-core/proto/"],
        )?;
    Ok(())
}
