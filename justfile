
build:
  cargo build --release --target wasm32-unknown-unknown
  cp ./target/wasm32-unknown-unknown/release/cvss.wasm ./cvss/0.1.0/src/
  
