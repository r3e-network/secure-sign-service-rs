// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::fs;
use std::io::Result;

fn main() -> Result<()> {
    // Create output directory if it doesn't exist
    fs::create_dir_all("src/neo")?;
    
    prost_build::Config::new()
        .out_dir("src/neo")
        // .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/signpb.proto"], &["proto/"])?;
    Ok(())
}
