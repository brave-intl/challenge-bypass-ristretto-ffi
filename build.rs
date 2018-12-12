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

    cc_build.cpp(true) // Switch to C++ library compilation.
    .flag("-std=c++11");

    if let Ok(ndebug) = ndebug {
        cc_build.flag(&("-NDEBUG=".to_owned() + &ndebug));
    }

    if let Ok(no_cxxexceptions) = no_cxxexceptions {
        cc_build.flag(&("-NNO_CXXEXCEPTIONS=".to_owned() + &no_cxxexceptions));
    }

    cc_build
    .file("src/wrapper.cpp")
    .compile("wrapper.a");
}

#[cfg(not(feature = "wrapper"))]
fn main() {
}
