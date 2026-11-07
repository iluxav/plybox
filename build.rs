use std::{env, fs, io::Write, path::PathBuf};

use flate2::{write::GzEncoder, Compression};
use sha2::{Digest, Sha512};

fn main() {
    println!("cargo:rerun-if-env-changed=PLYBOX_EMBED_RUNSC");
    println!("cargo:rerun-if-changed=third_party/gvisor/manifest.json");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let Some(root) = env::var_os("PLYBOX_EMBED_RUNSC") else {
        fs::write(out.join("gvisor_payload.rs"),
            "pub const RELEASE: Option<&str> = None;\npub const PAYLOAD_HASH: &str = \"\";\nstatic PAYLOAD: &[Payload] = &[];\n").unwrap();
        return;
    };
    assert!(!root.is_empty(), "PLYBOX_EMBED_RUNSC must name the verified runtime directory");
    let root = fs::canonicalize(root).expect("PLYBOX_EMBED_RUNSC: run make tools first");
    let manifest = fs::read("third_party/gvisor/manifest.json").unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(env::var("CARGO_CFG_TARGET_ARCH").unwrap(), "x86_64", "embedded gVisor is pinned for x86_64");
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").unwrap(), "linux", "embedded gVisor requires Linux");
    let mut source = format!("pub const RELEASE: Option<&str> = Some({:?});\npub const PAYLOAD_HASH: &str = {:?};\nstatic PAYLOAD: &[Payload] = &[\n",
        spec["release"].as_str().unwrap(), format!("{:x}", Sha512::digest(&manifest)));
    for (i, file) in spec["files"].as_array().unwrap().iter().enumerate() {
        let name = file["path"].as_str().unwrap();
        let path = root.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let data = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}; run make tools", path.display()));
        let hash = format!("{:x}", Sha512::digest(&data));
        assert_eq!(hash, file["sha512"].as_str().unwrap(), "{} differs from pinned gVisor; run make tools", path.display());
        assert_eq!(data.len() as u64, file["size"].as_u64().unwrap());
        let compressed = out.join(format!("gvisor-{i}.gz"));
        let mut gzip = GzEncoder::new(fs::File::create(&compressed).unwrap(), Compression::best());
        gzip.write_all(&data).unwrap();
        gzip.finish().unwrap();
        source.push_str(&format!("Payload {{ path: {name:?}, size: {}, sha512: {hash:?}, gzip: include_bytes!({:?}) }},\n", data.len(), compressed));
    }
    source.push_str("];\n");
    fs::write(out.join("gvisor_payload.rs"), source).unwrap();
}
