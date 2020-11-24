let pkgs = import <nixpkgs> {};
in pkgs.fetchFromGitHub {
  rev = builtins.readFile ./NIXPKGS_PIN;
  owner = "NixOS";
  repo = "nixpkgs";
  sha256 = "0182ys095dfx02vl2a20j1hz92dx3mfgz2a6fhn31bqlp1wa8hlq";
}
