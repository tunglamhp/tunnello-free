#[cfg(target_arch = "wasm32")]
fn main() {
    ddns_web::mount();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {}
