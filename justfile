
build:
  cargo build --release --target wasm32-unknown-unknown
  cp ./target/wasm32-unknown-unknown/release/cvss.wasm ./pkg
  
