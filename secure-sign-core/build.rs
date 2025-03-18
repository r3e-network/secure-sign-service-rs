// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .out_dir("src/neo")
        // .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/neo_signpb.proto"], &["proto/"])?;
    Ok(())
}
