with import <nixpkgs> {};

stdenv.mkDerivation {
    name = "ton";
    buildInputs = [
      nodejs yarn
      gcc boost174 cmake
      xxd
    ];
    shellHook = ''
        export PATH="$PWD/node_modules/.bin/:$PATH"
    '';
}
