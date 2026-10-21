{pkgs, ...}: {
  overlays = [
    (_: prev: {
      mold-unwrapped = prev.callPackage ./nix/mold.nix {};
    })
  ];

  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
    mold.enable = true;
  };

  # Clang's setup hook resets CC/CXX before enterShell runs.
  enterShell = ''
    export CC=${pkgs.stdenv.cc}/bin/cc
    export CXX=${pkgs.stdenv.cc}/bin/c++
  '';

  packages = with pkgs; [
    cargo-audit
    clang
    cmake
    curl
    gcc
    gnumake
    git
    gnutar
    patchelf
    p7zip
    xz
  ];
}
