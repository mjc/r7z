{pkgs, ...}: {
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
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
