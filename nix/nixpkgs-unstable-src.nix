let pkgs = import <nixpkgs> {};
in pkgs.fetchFromGitHub {
  rev = builtins.readFile ./NIXPKGS_UNSTABLE_PIN;
  owner = "NixOS";
  repo = "nixpkgs";
  sha256 = "0vr2di6z31c5ng73f0cxj7rj9vqvlvx3wpqdmzl0bx3yl3wr39y6";
}
