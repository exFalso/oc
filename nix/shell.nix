let
  pkgs = import ./nixpkgs.nix {};
  pkgs-src = import ./nixpkgs-src.nix;
in pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    cacert
  ];
}
