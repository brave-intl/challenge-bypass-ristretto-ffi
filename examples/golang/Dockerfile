FROM rustlang/rust:nightly as rust_builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools
COPY . /src
WORKDIR /src
RUN cargo build --target=x86_64-unknown-linux-musl 

FROM golang:1.14 as go_builder
RUN apt-get update && apt-get install -y valgrind
COPY --from=rust_builder /src/target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto_ffi.a /usr/lib/
COPY . /src
WORKDIR /src
RUN GO111MODULE=on go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.28.1
RUN make go-lint
RUN go build --ldflags '-extldflags "-static"' -o examples/golang.out examples/golang/main.go
RUN go build -o examples/golang.dyn.out examples/golang/main.go
RUN valgrind --suppressions=.valgrind.supp --run-libc-freeres=no --leak-check=yes --undef-value-errors=no --error-exitcode=1 examples/golang.dyn.out

FROM alpine:3.6
COPY --from=go_builder /src/examples/golang.out /bin/
CMD ["/bin/golang.out"]
