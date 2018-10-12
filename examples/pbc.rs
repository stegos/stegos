// -------------------------------------------------------------------
extern crate stegos_crypto;
extern crate rust_libpbc;

use stegos_crypto::pbc::*;

use std::sync::Mutex;

fn main() {

    fn init_pairings() {
        for info in CURVES {
            let context = info.context as u64;
            unsafe {
                println!("Init curve {}", (*info.name).to_string());
                println!("Context: {}", context);
                println!("{}", (*info.text).to_string());

                let mut psize = [0u64;4];
                let ans = rust_libpbc::init_pairing(
                    context,
                    info.text as *mut _,
                    (*info.text).len() as u64,
                    psize.as_ptr() as *mut _);
                assert_eq!(ans, 0);
                
                assert_eq!(psize[0], info.g1_size as u64);
                assert_eq!(psize[1], info.g2_size as u64);
                assert_eq!(psize[2], info.pairing_size as u64);
                assert_eq!(psize[3], info.field_size as u64);

                let mut v1 = vec![0u8; info.g1_size];
                hexstr_to_u8v(&(*info.g1), &mut v1);
                println!("G1: {}", u8v_to_hexstr(&v1));
                let len = rust_libpbc::set_g1(
                    context,
                    v1.as_ptr() as *mut _);
                // returns nbr bytes read, should equal length of G1
                assert_eq!(len, info.g1_size as i64);

                let mut v1 = vec![0u8; info.g1_size];
                let len = rust_libpbc::get_g1(
                    context,
                    v1.as_ptr() as *mut _,
                    info.g1_size as u64);
                assert_eq!(len, info.g1_size as u64);
                println!("G1 readback: {}", u8v_to_hexstr(&v1));
                
                let mut v2 = vec![0u8; info.g2_size];
                hexstr_to_u8v(&(*info.g2), &mut v2);
                println!("G2: {}", u8v_to_hexstr(&v2));
                let len = rust_libpbc::set_g2(
                    context,
                    v2.as_ptr() as *mut _);
                // returns nbr bytes read, should equal length of G2
                assert_eq!(len, info.g2_size as i64);

                let mut v2 = vec![0u8; info.g2_size];
                let len = rust_libpbc::get_g2(
                    context,
                    v2.as_ptr() as *mut _,
                    info.g2_size as u64);
                assert_eq!(len, info.g2_size as u64);
                println!("G2 readback: {}", u8v_to_hexstr(&v2));
                
            }
            println!("");
        }
    }
    // ------------------------------------------------------------------------
    // check connection to PBC library
    println!("Hello, world!");
    let input = "hello!".as_bytes();
    let output = vec![0u8; input.len()];
    unsafe {
        let echo_out = rust_libpbc::echo(
            input.len() as u64,
            input.as_ptr() as *mut _,
            output.as_ptr() as *mut _,
        );
        assert_eq!(echo_out, input.len() as u64);
        assert_eq!(input.to_vec(), output);
    }
    let out_str: String = std::str::from_utf8(&output).unwrap().to_string();
    println!("Echo Output: {}", out_str);
    println!("");

    // init PBC library -- must only be performed once
    let init = Mutex::new(false);
    {
        let mut done = init.lock().unwrap();
        if ! *done {
            *done = true;
            init_pairings();
        }
    }

    // test hashing
    let h = Hash::from_vector(b"");
    println!("hash(\"\") = {}", h.to_str());
    assert_eq!(h.to_str(), "H(a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a)");
    println!("");

    // -------------------------------------
    // on Secure pairings
    // test PRNG
    println!("rand Zr = {}", secure::Zr::random());

    // test keying...
    let (skey, pkey, sig) = secure::make_deterministic_keys(b"Testing");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(secure::check_keying(&pkey, &sig));
    println!("");

    // -------------------------------------
    // on Fast pairings
    // test PRNG
    println!("rand Zr = {}", fast::Zr::random());

    // test keying...
    let (skey, pkey, sig) = fast::make_deterministic_keys(b"Testing");
    println!("skey = {}", skey);
    println!("pkey = {}", pkey);
    println!("sig  = {}", sig);
    assert!(fast::check_keying(&pkey, &sig));

    // -------------------------------------
    // check some arithmetic on the Fast curves
    let a = 0x123456789i64;
    println!("chk Zr: 0x{:x} -> {}", a, fast::Zr::from_int(a));
    println!("chk Zr: -1 -> {}", fast::Zr::from_int(-1));
    println!("chk Zr: -1 + 1 -> {}", fast::Zr::from(-1) + 1);

    // -------------------------------------------
    let h = hash_nbytes(10, b"Testing");
    println!("h = {}", u8v_to_hexstr(&h));
    let h = hash_nbytes(64, b"Testing");
    println!("h = {}", u8v_to_hexstr(&h));
}
