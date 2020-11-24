let pkgs = import <nixpkgs> {};
in import (pkgs.fetchFromGitHub {
  rev = builtins.readFile ./CACHED_NIX_SHELL_PIN;
  owner = "xzfc";
  repo = "cached-nix-shell";
  sha256 = "0j39mqhvjrqkcx4yfaxlak4832bx9n2w6a5j0gfnq1a8spp5fj8a";
}) {}
