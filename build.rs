// build.rs

extern crate cc;

fn main() {
    cc::Build::new()
        .cpp(true) // Switch to C++ library compilation.
        .file("src/wrapper.cpp")
        .compile("wrapper.a");
}
