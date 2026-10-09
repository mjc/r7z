{lib, stdenv, stdenvNoCC, fetchurl, autoPatchelfHook}:
let
  hashes = {
    x86_64-linux = "sha256-bJDUpHTHwECd+1db4DpTRYeKwU/boY3otA+ljGASEYk=";
    aarch64-linux = "sha256-UsdZ02ibq66kxCry8xBip0q4Phf/tagJAjJTTGe3BXc=";
  };
in
stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "mold-unwrapped";
  version = "3.0.0";
  src = fetchurl {
    url = "https://github.com/rui314/mold/releases/download/v${finalAttrs.version}/mold-${finalAttrs.version}-${stdenv.hostPlatform.system}.tar.gz";
    hash = hashes.${stdenv.hostPlatform.system};
  };

  nativeBuildInputs = [autoPatchelfHook];
  buildInputs = [stdenv.cc.cc.lib];
  dontBuild = true;
  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    cp -r bin lib libexec share "$out/"
    runHook postInstall
  '';

  meta = {
    description = "High-performance ELF linker";
    homepage = "https://github.com/rui314/mold";
    license = lib.licenses.mit;
    platforms = builtins.attrNames hashes;
    mainProgram = "mold";
  };
})
