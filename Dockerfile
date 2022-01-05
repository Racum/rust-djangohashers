FROM rust:slim-buster AS rust_builder
RUN apt-get update && apt-get -y install libssl-dev && rm -rf /var/lib/apt/lists/*
RUN mkdir /repo && mkdir /repo/bin
ADD . /repo
WORKDIR /repo
RUN cargo build --example profile --release --no-default-features --features "with_pbkdf2" && \
    mv target/release/examples/profile bin/vanilla_profile && \
    cargo build --example profile --release --no-default-features --features "with_pbkdf2 fpbkdf2" && \
    mv target/release/examples/profile bin/fastpbkdf2_profile && \
    rm -rf target/release/examples

FROM python:3.10-slim-buster
RUN mkdir /app
WORKDIR /app
COPY --from=rust_builder /repo/bin/* /app/
RUN pip install django
ADD examples/profile.py .
CMD python profile.py && ./vanilla_profile && ./fastpbkdf2_profile
