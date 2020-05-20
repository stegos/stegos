extern crate libloading as lib;

fn call_dynamic() -> Result<u32, Box<dyn std::error::Error>> {
    let lib = lib::Library::new("libstegos.so")?;
    unsafe {
        let func: lib::Symbol<unsafe extern "C" fn() -> u32> = lib.get(b"init_rust")?;
        Ok(func())
    }
}

fn main() {
    call_dynamic().unwrap();
}
