CFLAGS :=
OS := $(shell uname -s | tr "[:upper:]" "[:lower:]")

ifeq (darwin,$(OS))
CFLAGS += -framework Security
endif

all: examples/cpp.out

examples/cpp.out: target/debug/libchallenge_bypass_ristretto.a examples/wrapper.o examples/cpp/main.cpp 
	g++ $(CFLAGS) -std=gnu++0x examples/cpp/main.cpp examples/wrapper.o ./target/debug/libchallenge_bypass_ristretto.a -I ./src -lpthread -ldl -o examples/cpp.out

examples/wrapper.o: src/lib.h src/wrapper.cpp src/wrapper.hpp
	g++ $(CFLAGS) -std=gnu++0x src/wrapper.cpp -I src/ -c  -o examples/wrapper.o

target/debug/libchallenge_bypass_ristretto.a: src/lib.rs Cargo.toml
	cargo build

examples/golang.out: target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto.a examples/golang/main.go lib.go src/lib.h
	go build --ldflags '-extldflags "-static"' -o examples/golang.out examples/golang/main.go

target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto.a: src/lib.rs Cargo.toml
	cargo build --target=x86_64-unknown-linux-musl

go-docker:
	docker build -f examples/golang/Dockerfile -t challenge-bypass-ristretto-ffi-go .

go-docker-test: go-docker
	docker run -i challenge-bypass-ristretto-ffi-go

go-lint:
	golangci-lint run -E gofmt -E golint -D megacheck -D typecheck --exclude-use-default=false lib.go
	golangci-lint run -E gofmt -E golint --exclude-use-default=false examples/golang/main.go

clean:
	rm -rf target

lint: go-lint
	cargo fmt -- --check
	cargo clippy
