extern crate bindgen;
extern crate cc;

fn main() {
    let mut buildc = cc::Build::new();
    let tool = buildc.get_compiler();
    if tool.is_like_clang() || tool.is_like_gnu() {
        buildc
            .flag_if_supported("-msse4.1")
            .flag_if_supported("-maes");
    }
    buildc
        .define("__RUST_RAW_CRYPTO__", Some("1"))
        .file("external/crypto/crypto-ops.c")
        .file("external/crypto/hash.c")
        .file("external/crypto/keccak.c")
        .file("external/crypto/memwipe.c")
        .compile("crypto-ops");

    let mut buildcpp = cc::Build::new();
    buildcpp.cpp(true);
    buildcpp
        .flag("-std=c++11")
        .include("external/crypto")
        .file("external/crypto/crypto.cpp")
        .file("external/hex/hex.cpp")
        .compile("crypto");
}

