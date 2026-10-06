# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Optional identity, object storage, metrics, logs, traces, and dashboard services.
# The addons role is fixed at evaluation because certificates and OAuth redirects
# share its configured domain. Secrets remain runtime files outside the store.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack.addons;
  enabled = builtins.elem "addons" config.meisterstack.roles;

  pki = config.meisterstack.pki.dir;
  state = "/var/lib/meister-data/addons";
  ports = (import ./lib/ports.nix).addons;

  # Fixed names for addon credentials in the runtime PKI directory.
  adminPassword = "${pki}/addons-admin";
  grafanaSecret = "${pki}/addons-grafana-secret";
  garageEnv = "${pki}/addons-garage.env";

  # Kanidm exposes one issuer per OAuth2 client; inventory derives this same URL.
  origin = "https://${cfg.fqdn}:${toString ports.kanidm}";

  # Bind persistent state onto each service module's expected path. DynamicUser
  # services use /var/lib/private so the public symlink remains available.
  stateDirs = {
    "/var/lib/kanidm" = "kanidm";
    "/var/lib/${config.services.prometheus.stateDir}" = "prometheus";
    "/var/lib/loki" = "loki";
    "/var/lib/private/tempo" = "tempo";
    "/var/lib/grafana" = "grafana";
    "/var/lib/private/garage" = "garage";
  };

  # Set ownership behind bind mounts for services without StateDirectory ownership handling.
  stateOwners = {
    loki = "loki";
    grafana = "grafana";
  };

  # Wait for the serving credentials and, when present, the role renderer.
  gated = extra: {
    # Order after rendering; request the renderer only when its unit exists.
    after = [ "meister-context.service" ];
    wants = lib.mkIf config.meisterstack.context.enable [ "meister-context.service" ];
    # Require a role marker only when a renderer creates one. Managed role selection
    # is fixed by the evaluated system.
    unitConfig.ConditionPathExists =
      lib.optional config.meisterstack.context.enable
        "${config.meisterstack.configDir}/addons.enabled"
      ++ [ "${pki}/serving.crt" ] ++ extra;
  };
in
{
  options.meisterstack.addons = {
    fqdn = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
      description = ''
        The name this box is reached under. It is the Kanidm origin, the
        issuer, the name in the serving certificate and the host in every
        oauth2 redirect url at once — so it is a NAME and not an address, it
        has to resolve on every machine that logs in, and the CA that signs
        the serving certificate has to have signed it.
      '';
    };

    scrapeTargets = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "10.0.0.10:9100" "10.0.0.11:9102" ];
      description = ''
        The `meister` scrape job, one entry per node AND role: a box with two
        roles has two metrics listeners (9100 cloud, 9101 cluster, 9102
        agent). A fleet inventory derives this from the plan; the lab's twelve vms
        are twelve targets, not thirty-six.
      '';
    };

    retention = lib.mkOption {
      type = lib.types.str;
      default = "7d";
      description = "How long Prometheus keeps series. A lab box, not an archive.";
    };
  };

  config = lib.mkIf enabled {
    # Create persistent directories before bind mounts, and order their creation
    # after the data filesystem. Keep service-native state paths.
    systemd.services.meister-addons-dirs = {
      description = "Subdirectories for the addons state on the data block";
      unitConfig.RequiresMountsFor = "/var/lib/meister-data";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = [
          ("${pkgs.coreutils}/bin/mkdir -p "
            + lib.concatMapStringsSep " " (d: "${state}/${d}") (lib.attrValues stateDirs)
            # Create the backup directory required by Kanidm's filesystem sandbox.
            + " ${state}/kanidm/backups")
        ] ++ lib.mapAttrsToList
          (dir: owner: "${pkgs.coreutils}/bin/chown -R ${owner}:${owner} ${state}/${dir}")
          stateOwners
        ++ [ "${pkgs.coreutils}/bin/chown kanidm:kanidm ${state}/kanidm/backups" ];
      };
    };

    # An optional absent data disk leaves addon state on the root filesystem.
    fileSystems = lib.mapAttrs'
      (mountPoint: dir: lib.nameValuePair mountPoint {
        device = "${state}/${dir}";
        options = [
          "bind"
          "nofail"
          "x-systemd.requires=meister-addons-dirs.service"
          "x-systemd.after=meister-addons-dirs.service"
        ];
      })
      stateDirs;

    # Serve the identity provider over TLS using runtime credentials.
    services.kanidm = {
      # Select Kanidm 1.10 with file-based secret provisioning support. Database
      # version upgrades require their own migration procedure.
      package = pkgs.kanidmWithSecretProvisioning_1_10;
      enableServer = true;
      serverSettings = {
        domain = cfg.fqdn;
        inherit origin;
        bindaddress = "0.0.0.0:${toString ports.kanidm}";
        # Load credentials through systemd so Kanidm can read private key copies
        # without broadening permissions on the original PEM files.
        tls_chain = "/run/credentials/kanidm.service/tls-chain";
        tls_key = "/run/credentials/kanidm.service/tls-key";
        # The module owns db_path; the bind mount supplies persistence. Backups are
        # not configured by this example.
        online_backup.enabled = false;
      };

      # Provision accounts and clients declaratively; finish user credential setup
      # through Kanidm administration.
      provision = {
        enable = true;
        # Provision through loopback to avoid depending on external name resolution.
        instanceUrl = "https://localhost:${toString ports.kanidm}";
        acceptInvalidCerts = true;
        # Give the post-start provisioner its own readable credential copy.
        idmAdminPasswordFile = "/run/credentials/kanidm.service/idm-admin";

        groups = {
          # These groups label identity-provider roles. Cloud User objects independently
          # authorize MeisterStack API requests.
          meister-admins = { };
          meister-operators = { };
          meister-members = { };
          meister-viewers = { };
        };

        persons = {
          silas = {
            displayName = "Silas";
            mailAddresses = [ "silas@${cfg.fqdn}" ];
            groups = [ "meister-admins" ];
          };
          alice = {
            displayName = "Alice";
            mailAddresses = [ "alice@${cfg.fqdn}" ];
            groups = [ "meister-members" ];
          };
          bob = {
            displayName = "Bob";
            mailAddresses = [ "bob@${cfg.fqdn}" ];
            groups = [ "meister-viewers" ];
          };
          carol = {
            displayName = "Carol";
            mailAddresses = [ "carol@${cfg.fqdn}" ];
            groups = [ "meister-operators" ];
          };
        };

        systems.oauth2 = {
          meister-cli = {
            displayName = "MeisterStack CLI";
            # Use a public PKCE client for native loopback redirects.
            public = true;
            enableLocalhostRedirects = true;
            originUrl = "http://localhost:8400/callback";
            originLanding = origin;
            # Map preferred_username to the account name used by the cloud directory.
            preferShortUsername = true;
            scopeMaps.meister-viewers = [ "openid" "profile" "email" ];
            scopeMaps.meister-members = [ "openid" "profile" "email" ];
            scopeMaps.meister-operators = [ "openid" "profile" "email" ];
            scopeMaps.meister-admins = [ "openid" "profile" "email" ];
          };
          grafana = {
            displayName = "Grafana";
            # Share the OAuth client secret through separate credentials for Kanidm and Grafana.
            basicSecretFile = "/run/credentials/kanidm.service/grafana-secret";
            originUrl = "http://${cfg.fqdn}:3080/login/generic_oauth";
            originLanding = "http://${cfg.fqdn}:3080/";
            preferShortUsername = true;
            scopeMaps.meister-viewers = [ "openid" "profile" "email" ];
            scopeMaps.meister-admins = [ "openid" "profile" "email" ];
            claimMaps.groups = {
              joinType = "array";
              valuesByGroup.meister-admins = [ "admin" ];
              valuesByGroup.meister-viewers = [ "viewer" ];
            };
          };
        };
      };
    };
    systemd.services.kanidm = gated [ "${pki}/serving.key" adminPassword grafanaSecret ] // {
      serviceConfig.LoadCredential = [
        "tls-chain:${pki}/serving.crt"
        "tls-key:${pki}/serving.key"
        "idm-admin:${adminPassword}"
        "grafana-secret:${grafanaSecret}"
      ];
    };
    systemd.services.kanidm-provision = gated [ adminPassword grafanaSecret ];

    # Single-node object storage, with replication factor one.
    services.garage = {
      # Enable the Garage service as well as its configuration.
      enable = true;
      package = pkgs.garage_2;
      # Read Garage secrets from a runtime environment file.
      environmentFile = garageEnv;
      settings = {
        metadata_dir = "/var/lib/garage/meta";
        data_dir = "/var/lib/garage/data";
        db_engine = "sqlite";
        replication_factor = 1;
        rpc_bind_addr = "127.0.0.1:3901";
        rpc_public_addr = "127.0.0.1:3901";
        s3_api = {
          api_bind_addr = "0.0.0.0:3900";
          s3_region = "garage";
          root_domain = ".s3.${cfg.fqdn}";
        };
        admin.api_bind_addr = "0.0.0.0:3903";
      };
    };
    systemd.services.garage = gated [ garageEnv ];

    # Scrape each configured host and role separately.
    services.prometheus = {
      enable = true;
      port = 9090;
      retentionTime = cfg.retention;
      globalConfig.scrape_interval = "15s";
      scrapeConfigs = [
        {
          job_name = "meister";
          static_configs = [{ targets = cfg.scrapeTargets; }];
        }
        {
          job_name = "prometheus";
          static_configs = [{ targets = [ "127.0.0.1:9090" ]; }];
        }
      ];
    };
    systemd.services.prometheus = gated [ ];

    # Store logs in a single Loki process with filesystem storage.
    services.loki = {
      enable = true;
      configuration = {
        auth_enabled = false;
        server.http_listen_port = ports.loki;
        server.grpc_listen_port = 9096;
        common = {
          path_prefix = "/var/lib/loki";
          replication_factor = 1;
          ring.kvstore.store = "inmemory";
          ring.instance_addr = "127.0.0.1";
          storage.filesystem = {
            chunks_directory = "/var/lib/loki/chunks";
            rules_directory = "/var/lib/loki/rules";
          };
        };
        schema_config.configs = [{
          from = "2026-01-01";
          store = "tsdb";
          object_store = "filesystem";
          schema = "v13";
          index = { prefix = "index_"; period = "24h"; };
        }];
        limits_config = {
          reject_old_samples = false;
          allow_structured_metadata = true;
        };
      };
    };
    systemd.services.loki = gated [ ];

    # Receive OTLP directly from the runtime binaries.
    services.tempo = {
      enable = true;
      settings = {
        server = {
          http_listen_port = 3200;
          grpc_listen_port = 9095;
        };
        distributor.receivers.otlp.protocols = {
          grpc.endpoint = "0.0.0.0:${toString ports.otlp}";
          http.endpoint = "0.0.0.0:4318";
        };
        storage.trace = {
          backend = "local";
          local.path = "/var/lib/tempo/blocks";
          wal.path = "/var/lib/tempo/wal";
        };
      };
    };
    systemd.services.tempo = gated [ ];

    # Dashboard and identity-provider integration.
    services.grafana = {
      enable = true;
      settings = {
        server = {
          http_addr = "0.0.0.0";
          # Use port 3080 to avoid the cloud API on port 3000.
          http_port = 3080;
          root_url = "http://${cfg.fqdn}:3080/";
        };
        database.type = "sqlite3";
        # Retain a local administrator for identity-provider outages.
        security.admin_user = "admin";
        "auth.generic_oauth" = {
          enabled = true;
          name = "MeisterStack";
          client_id = "grafana";
          # Read the OAuth secret through Grafana's systemd credential copy.
          client_secret = "$__file{/run/credentials/grafana.service/oauth-secret}";
          scopes = "openid profile email";
          auth_url = "${origin}/ui/oauth2";
          token_url = "${origin}/oauth2/token";
          api_url = "${origin}/oauth2/openid/grafana/userinfo";
          use_pkce = true;
          # Trust the configured CA for identity-provider HTTPS.
          tls_client_ca = "${pki}/ca.crt";
          # Map the configured Grafana role claim.
          role_attribute_path = "contains(groups[*], 'admin') && 'Admin' || 'Viewer'";
        };
      };
      provision = {
        enable = true;
        datasources.settings.datasources = [
          {
            name = "Prometheus";
            type = "prometheus";
            uid = "meister-prometheus";
            url = "http://127.0.0.1:9090";
            isDefault = true;
          }
          {
            name = "Loki";
            type = "loki";
            uid = "meister-loki";
            url = "http://127.0.0.1:${toString ports.loki}";
            jsonData.derivedFields = [{
              # Match the flattened span trace-ID field for a Tempo link.
              name = "TraceID";
              matcherRegex = "\"span_trace_id\":\"(\\w+)\"";
              url = "\${__value.raw}";
              datasourceUid = "meister-tempo";
            }];
          }
          {
            name = "Tempo";
            type = "tempo";
            uid = "meister-tempo";
            url = "http://127.0.0.1:3200";
          }
        ];
      };
    };
    systemd.services.grafana = gated [ grafanaSecret ] // {
      serviceConfig.LoadCredential = [ "oauth-secret:${grafanaSecret}" ];
    };

    # Provide the Kanidm CLI for account credential setup.
    environment.systemPackages = [ pkgs.kanidm_1_10 ];
  };
}
