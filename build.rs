// build.rs

#[cfg(feature = "wrapper")]
extern crate cc;

#[cfg(feature = "wrapper")]
use std::env;

#[cfg(feature = "wrapper")]
fn main() {
    let ndebug = env::var("NDEBUG");
    let no_cxxexceptions = env::var("NO_CXXEXCEPTIONS");

    let mut cc_build = cc::Build::new();

    cc_build
        .cpp(true) // Switch to C++ library compilation.
        .flag("-std=c++11");

    // For iOS targets we actually need to override the default minimum ios version thats
    // set in cc::Build due to needing support for `thread_local`
    if let Ok(target) = env::var("TARGET") {
        if target == "aarch64-apple-ios" {
            cc_build.flag("-miphoneos-version-min=12.0");
        } else if target == "x86_64-apple-ios" {
            cc_build.flag("-miphonesimulator-version-min=12.0");
        }
    }

    if let Ok(ndebug) = ndebug {
        cc_build.flag(&("-DNDEBUG=".to_owned() + &ndebug));
    }

    if let Ok(no_cxxexceptions) = no_cxxexceptions {
        cc_build.flag(&("-DNO_CXXEXCEPTIONS=".to_owned() + &no_cxxexceptions));
    }

    cc_build.file("src/wrapper.cpp").compile("wrapper.a");
}

#[cfg(not(feature = "wrapper"))]
fn main() {}
