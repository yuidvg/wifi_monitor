{
  description = "Wi-Fi diagnostics for macOS";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
  outputs =
    { nixpkgs, ... }:
    {
      packages = nixpkgs.lib.genAttrs [ "aarch64-darwin" "x86_64-darwin" ] (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          monitor = pkgs.writeScriptBin "wifi-monitor" ''
            #!${pkgs.python3}/bin/python3
            ${builtins.readFile ./wifi_monitor.py}
          '';
        in
        {
          default = monitor;
          wifi-monitor = monitor;
        }
      );
    };
}
