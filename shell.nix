with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "rucredstash";
  buildInputs = [
    pkg-config
    openssl
  ];
}
