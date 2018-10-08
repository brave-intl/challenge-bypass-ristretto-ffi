all: target/debug/libchallenge_bypass_ristretto.a wrappers.o
	g++ src/main.cpp wrapper.o -I src/ -L ./target/debug/ -lchallenge_bypass_ristretto -lpthread -ldl -o run
	LD_LIBRARY_PATH=./target/debug/ ./run

wrappers.o:
	g++ src/wrapper.cpp -I src/ -c 

target/debug/libchallenge_bypass_ristretto.a: src/lib.rs Cargo.toml
	cargo build

clean:
	rm -rf target
