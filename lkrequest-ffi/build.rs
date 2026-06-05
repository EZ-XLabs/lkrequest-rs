use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let header_path = manifest_dir.join("include").join("lkrequest.h");

    // The C header is a build artifact for non-Rust consumers, not a
    // compile-time input for this crate, and it is intentionally not committed.
    // Regenerate it when cbindgen is available; otherwise skip with a warning
    // rather than failing the build (the Rust crate compiles fine without it).
    match generate_header(&manifest_dir) {
        Ok(header) => write_header(&header_path, &header),
        Err(err) => println!(
            "cargo:warning=skipping cbindgen FFI header generation ({err}); \
             install cbindgen to refresh {}",
            header_path.display()
        ),
    }
}

fn generate_header(manifest_dir: &Path) -> Result<Vec<u8>, String> {
    let cbindgen = env::var("CBINDGEN").unwrap_or_else(|_| "cbindgen".to_string());
    let output = Command::new(&cbindgen)
        .current_dir(manifest_dir)
        .arg(".")
        .arg("--config")
        .arg("cbindgen.toml")
        .output()
        .map_err(|err| format!("failed to run '{cbindgen}': {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "cbindgen failed while generating headers:\n{stderr}"
        ));
    }

    Ok(output.stdout)
}

fn write_header(path: &Path, header: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("failed to create '{}': {err}", parent.display()));
    }
    match fs::read(path) {
        Ok(existing) if existing == header => {}
        Ok(_) | Err(_) => fs::write(path, header)
            .unwrap_or_else(|err| panic!("failed to write '{}': {err}", path.display())),
    }
}
