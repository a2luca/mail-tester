{
  description = "mailtest – auto-responder that replies with an SPF/DKIM/DMARC report";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-linux"];
    forSystems = flake-utils.lib.eachSystem supportedSystems;
  in
    forSystems (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python311;

        mailtest = python.pkgs.buildPythonApplication {
          pname = "mailtest";
          version = "0.1.0";
          pyproject = true;

          src = ./.;

          build-system = [python.pkgs.hatchling];

          dependencies = [python.pkgs.dnspython];

          nativeCheckInputs = [python.pkgs.pytestCheckHook python.pkgs.dnspython];
          pytestFlags = ["tests/"];

          meta = {
            description = "Auto-responder that replies with an SPF/DKIM/DMARC report";
            mainProgram = "mailtest";
          };
        };
        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "mailtest";
          tag = "latest";

          contents = [
            mailtest
            pkgs.cacert
            pkgs.tzdata
          ];

          fakeRootCommands = ''
            mkdir -p /data
            chown 1000:1000 /data
          '';
          enableFakechroot = true;

          config = {
            Entrypoint = ["${mailtest}/bin/mailtest"];
            User = "1000";
            Volumes = {"/data" = {};};
            Env = ["DB_PATH=/data/state.db"];
          };
        };
      in {
        packages.default = mailtest;
        packages.dockerImage = dockerImage;

        devShells.default = pkgs.mkShell {
          packages = [
            python
            python.pkgs.dnspython
            python.pkgs.pytest
            pkgs.ruff
            pkgs.alejandra
            pkgs.deadnix
            pkgs.statix
          ];
          shellHook = ''
            export PYTHONPATH=$PWD/src
          '';
        };

        checks = {
          package = mailtest;
          nixos-module =
            (nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                self.nixosModules.default
                {
                  services.mailtest = {
                    enable = true;
                    imapHost = "mail.example.com";
                    user = "mail-test@example.com";
                    myHostname = "mail.example.com";
                    environmentFile = "/run/secrets/mailtest";
                  };
                  system.stateVersion = "24.11";
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "none";
                    fsType = "tmpfs";
                  };
                }
              ];
            }).config.system.build.toplevel;
        };
      }
    )
    // {
      nixosModules.default = {
        config,
        lib,
        pkgs,
        ...
      }: let
        cfg = config.services.mailtest;
        pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      in {
        options.services.mailtest = {
          enable = lib.mkEnableOption "mailtest auto-responder";

          package = lib.mkOption {
            type = lib.types.package;
            default = pkg;
            description = "The mailtest package to use.";
          };

          imapHost = lib.mkOption {
            type = lib.types.str;
            description = "IMAP server hostname.";
          };

          imapPort = lib.mkOption {
            type = lib.types.port;
            default = 993;
            description = "IMAP server port.";
          };

          smtpHost = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "SMTP server hostname (defaults to imapHost).";
          };

          smtpPort = lib.mkOption {
            type = lib.types.port;
            default = 587;
            description = "SMTP server port.";
          };

          user = lib.mkOption {
            type = lib.types.str;
            description = "Mail address used to log in (MAIL_USER).";
          };

          myHostname = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "Hostname of your MX as it appears in Received headers.";
          };

          triggerSubject = lib.mkOption {
            type = lib.types.str;
            default = "Mailtest";
            description = "Subject line that triggers a reply.";
          };

          folders = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = ["INBOX" "Junk"];
            description = "IMAP folders to poll.";
          };

          alertTo = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "Address to receive daily over-use alerts.";
          };

          alertThreshold = lib.mkOption {
            type = lib.types.int;
            default = 5;
            description = "Number of daily uses that trigger an alert.";
          };

          perSenderLimitPerHour = lib.mkOption {
            type = lib.types.int;
            default = 5;
            description = "Max replies per sender per hour.";
          };

          pollSeconds = lib.mkOption {
            type = lib.types.int;
            default = 30;
            description = "IMAP poll interval in seconds.";
          };

          companyName = lib.mkOption {
            type = lib.types.str;
            default = "Luca Lutz Networks";
            description = "Company name shown in the reply mail.";
          };

          contactAddress = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "Contact address shown in the reply mail.";
          };

          websiteUrl = lib.mkOption {
            type = lib.types.str;
            default = "https://lucalutz.net";
            description = "Website URL linked in the reply mail.";
          };

          logoUrl = lib.mkOption {
            type = lib.types.str;
            default = "https://lucalutz.net/logo-llwn.png";
            description = "Logo image URL (use PNG, not SVG).";
          };

          timeZone = lib.mkOption {
            type = lib.types.str;
            default = "Europe/Berlin";
            description = "Timezone for timestamps in the report.";
          };

          environmentFile = lib.mkOption {
            type = lib.types.path;
            description = ''
              Path to a file containing MAIL_PASSWORD=... (and optionally
              other secrets). Loaded by systemd EnvironmentFile — the file
              never enters the Nix store. Compatible with sops-nix and agenix.
            '';
          };

          extraEnvironment = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
            description = "Additional environment variables passed to the service.";
          };
        };

        config = lib.mkIf cfg.enable {
          systemd.services.mailtest = {
            description = "mailtest auto-responder";
            after = ["network-online.target"];
            wants = ["network-online.target"];
            wantedBy = ["multi-user.target"];

            serviceConfig = {
              ExecStart = "${cfg.package}/bin/mailtest";
              Restart = "always";
              RestartSec = "10s";
              DynamicUser = true;
              StateDirectory = "mailtest";
              EnvironmentFile = cfg.environmentFile;

              # Hardening
              ProtectSystem = "strict";
              ProtectHome = true;
              PrivateTmp = true;
              NoNewPrivileges = true;
              RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
              SystemCallFilter = "@system-service";
              CapabilityBoundingSet = "";
              LockPersonality = true;
              RestrictRealtime = true;
              RestrictSUIDSGID = true;
              MemoryDenyWriteExecute = true;
              PrivateDevices = true;
            };

            environment =
              {
                IMAP_HOST = cfg.imapHost;
                IMAP_PORT = toString cfg.imapPort;
                SMTP_HOST =
                  if cfg.smtpHost != ""
                  then cfg.smtpHost
                  else cfg.imapHost;
                SMTP_PORT = toString cfg.smtpPort;
                MAIL_USER = cfg.user;
                MAIL_ADDRESS = cfg.user;
                MY_HOSTNAME = cfg.myHostname;
                TRIGGER_SUBJECT = cfg.triggerSubject;
                FOLDERS = lib.concatStringsSep "," cfg.folders;
                ALERT_TO = cfg.alertTo;
                ALERT_THRESHOLD = toString cfg.alertThreshold;
                PER_SENDER_LIMIT_PER_HOUR = toString cfg.perSenderLimitPerHour;
                POLL_SECONDS = toString cfg.pollSeconds;
                COMPANY_NAME = cfg.companyName;
                CONTACT_ADDRESS = cfg.contactAddress;
                WEBSITE_URL = cfg.websiteUrl;
                LOGO_URL = cfg.logoUrl;
                TZ = cfg.timeZone;
                DB_PATH = "/var/lib/mailtest/state.db";
              }
              // cfg.extraEnvironment;
          };
        };
      };
    };
}
