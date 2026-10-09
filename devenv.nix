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
