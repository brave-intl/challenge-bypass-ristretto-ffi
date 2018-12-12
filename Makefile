CFLAGS :=
OS := $(shell uname -s | tr "[:upper:]" "[:lower:]")

ifeq (darwin,$(OS))
CFLAGS += -framework Security
endif

ifdef NDEBUG
CFLAGS += -DNDEBUG=${NDEBUG}
endif

ifdef NO_CXXEXCEPTIONS
CFLAGS += -DNO_CXXEXCEPTIONS=${NO_CXXEXCEPTIONS}
endif

all: examples/cpp.out

examples/cpp.out: target/debug/libchallenge_bypass_ristretto.a examples/cpp/main.cpp 
	g++ $(CFLAGS) -std=gnu++0x examples/cpp/main.cpp ./target/debug/libchallenge_bypass_ristretto.a -I ./src -lpthread -ldl -o examples/cpp.out

target/debug/libchallenge_bypass_ristretto.a: src/lib.rs Cargo.toml
	cargo build

examples/golang.out: target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto.a examples/golang/main.go lib.go src/lib.h
	go build --ldflags '-extldflags "-static"' -o examples/golang.out examples/golang/main.go

examples/golang.dyn.out: target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto.a examples/golang/main.go lib.go src/lib.h
	go build -o examples/golang.dyn.out examples/golang/main.go

target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto.a: src/lib.rs Cargo.toml
	cargo build --target=x86_64-unknown-linux-musl

go-docker:
	docker build -f examples/golang/Dockerfile -t challenge-bypass-ristretto-ffi-go .

go-docker-test: go-docker
	docker run -i challenge-bypass-ristretto-ffi-go

go-lint:
	golangci-lint run -E gofmt -E golint -D megacheck -D typecheck -D structcheck --exclude-use-default=false lib.go
	golangci-lint run -E gofmt -E golint --exclude-use-default=false examples/golang/main.go

clean:
	rm -rf target

lint: go-lint
	cargo fmt -- --check
	cargo clippy
