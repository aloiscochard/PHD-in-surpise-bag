with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "rust-env";
  nativeBuildInputs = [
    # rustc cargo
    rustup
  ];
  buildInputs = [
    openssl
  ];
  RUST_BACKTRACE = 1;
  OPENSSL_DIR=openssl.out;
  OPENSSL_INCLUDE_DIR=openssl.dev;
}
