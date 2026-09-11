# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The fourth role: the six services this stack talks TO rather than consists
# of — an identity provider, an object store, and the three halves of
# observability with a window onto them.
#
# They live here because k3s was the only unstable thing in the lab and
# because a MeisterStack that needs a Kubernetes to be logged into is not a
# story anybody wants to tell. One box, six systemd units, each with the user
# and the sandbox its nixpkgs module brings, state on one data block.
#
# BUILD TIME, and that is a decision rather than an oversight. The other three
# roles are decided at boot because their only per-machine values are
# addresses, and an address is a fact about where a vm was started. These six
# are different: Kanidm's `origin`, every oauth2 redirect url, Grafana's
# root_url and the name in the serving certificate are all THE SAME NAME, and
# that name has to be known before `keys init` signs anything. A deployment
# that knows its own fqdn can name it in the plan, and a plan node bakes it —
# so `meisterstack.roles = [ ... "addons" ]` is what turns this file on, and
# the generic OpenNebula image (roles = [ ]) does not carry these six at all.
# one-context says so in one sentence if a context asks for addons on an image
# built without them, which is a better answer than six units that are present
# and misconfigured.
#
# No secret is in the nix store. The four files below are pushed to
# /opt/meisterstack/pki the way certificates are (`meister-deploy keys push`),
# and every unit here waits for the ones it needs with ConditionPathExists —
# the same rule the controllers follow, and for the same reason: a service
# that has not been given its credentials yet should be visibly skipped, not
# restarting every two seconds.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack.addons;
  enabled = builtins.elem "addons" config.meisterstack.roles;

  pki = "/opt/meisterstack/pki";
  state = "/var/lib/meister-data/addons";

  # What `meister-deploy keys init` writes into the CA directory and `keys
  # push` puts here. Names are fixed, like serving.crt and identity.crt.
  adminPassword = "${pki}/addons-admin";
  grafanaSecret = "${pki}/addons-grafana-secret";
  garageEnv = "${pki}/addons-garage.env";

  # Kanidm publishes one issuer PER OAUTH2 CLIENT, so the cloud's issuer is
  # "${origin}/oauth2/openid/meister-cli" — and nix/fleet.nix derives exactly
  # that string for MEISTER_OIDC_ISSUER. The two have to agree, and this
  # comment is where a reader finds out that they do.
  origin = "https://${cfg.fqdn}:8443";

  # Where each of the six keeps its state: the mount point its module already
  # uses, and the directory on the data block that is bound onto it.
  #
  # `tempo` and `garage` are named under /var/lib/PRIVATE, and that is not a
  # detail. Both run under DynamicUser, and for those systemd does not make
  # /var/lib/<name> a directory at all: it makes /var/lib/private/<name> and
  # leaves /var/lib/<name> as a SYMLINK to it. A mount sitting where that
  # symlink belongs makes every single start fail before the binary runs —
  #
  #   tempo.service: Failed to set up special execution directory in
  #   /var/lib: Device or resource busy
  #
  # — which is what the lab measured the first time this role was booted.
  stateDirs = {
    "/var/lib/kanidm" = "kanidm";
    "/var/lib/${config.services.prometheus.stateDir}" = "prometheus";
    "/var/lib/loki" = "loki";
    "/var/lib/private/tempo" = "tempo";
    "/var/lib/grafana" = "grafana";
    "/var/lib/private/garage" = "garage";
  };

  # Who must own the directory BEHIND the mount, where systemd does not do it.
  #
  # A service with `StateDirectory=` gets its directory chowned on every
  # start, mount or no mount (kanidm and prometheus, and the two DynamicUser
  # ones above). The other two are plain `User=` services whose nixpkgs
  # module chowns a path at activation time — and the mount that lands on
  # that path afterwards hides the chown behind it. Measured: loki died with
  # `mkdir /var/lib/loki/rules: permission denied` and grafana with
  # `ln: failed to create symbolic link '/var/lib/grafana/conf'`.
  stateOwners = {
    loki = "loki";
    grafana = "grafana";
  };

  # Every unit of this role waits for the same two things: the serving pair
  # from the lab CA, and the marker one-context writes when the role is named.
  gated = extra: {
    # After one-context, like every other unit here: it is what writes the
    # marker, and a condition evaluated on a file that is about to appear is a
    # unit that stays skipped while everybody wonders why.
    after = [ "one-context.service" ];
    wants = [ "one-context.service" ];
    unitConfig.ConditionPathExists = [
      "/run/meisterstack/addons.enabled"
      "${pki}/serving.crt"
    ] ++ extra;
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
        has to resolve on every machine that logs in, and `meister-deploy keys
        init` has to have signed it.
      '';
    };

    scrapeTargets = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "10.0.0.10:9100" "10.0.0.11:9102" ];
      description = ''
        The `meister` scrape job, one entry per node AND role: a box with two
        roles has two metrics listeners (9100 cloud, 9101 cluster, 9102
        agent). nix/fleet.nix derives this from the plan; the lab's twelve vms
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
    # --- the state of all six, on the data block ---------------------------
    #
    # One rule for all of them, and it is the boring one: every service keeps
    # its module's OWN state path, and the data block is bind-mounted onto it.
    # The alternative — pointing six configurations at subdirectories of the
    # block — collides with three different things at once (kanidm's db_path
    # is read-only in its module, prometheus has no absolute path at all, and
    # tempo runs under DynamicUser so nothing but StateDirectory= can get the
    # ownership right). A mount has none of those problems: systemd creates
    # the state directory behind it and chowns it, and the service is none
    # the wiser.
    #
    # The subdirectories have to exist BEFORE those mounts, and tmpfiles runs
    # after local-fs.target — which is the exact ordering that once put etcd
    # on the root disk without a word. So the mounts require this unit by
    # name, and it requires the block.
    systemd.services.meister-addons-dirs = {
      description = "Subdirectories for the addons state on the data block";
      unitConfig.RequiresMountsFor = "/var/lib/meister-data";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = [
          ("${pkgs.coreutils}/bin/mkdir -p "
            + lib.concatMapStringsSep " " (d: "${state}/${d}") (lib.attrValues stateDirs)
            # kanidm's unit carries `BindPaths=/var/lib/kanidm/backups`, and a
            # bind path that does not exist is not a warning, it is
            # `status=226/NAMESPACE` before the daemon runs. The module makes
            # it under its StateDirectory; behind our mount there is nothing
            # to make it, so it is made here.
            + " ${state}/kanidm/backups")
        ] ++ lib.mapAttrsToList
          (dir: owner: "${pkgs.coreutils}/bin/chown -R ${owner}:${owner} ${state}/${dir}")
          stateOwners
        ++ [ "${pkgs.coreutils}/bin/chown kanidm:kanidm ${state}/kanidm/backups" ];
      };
    };

    # Absent block, absent mount (nofail), and the six then live on the root
    # disk — a lab box that was never given a second disk still comes up, and
    # `meister-deploy check` is where that shows.
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

    # --- the identity provider ---------------------------------------------
    #
    # TLS is not optional here and never was: shared/oidc speaks https only,
    # deliberately, because that channel is how the cloud fetches the keys it
    # checks token signatures against. The pair comes from the lab CA, the
    # same one that signs the fleet, and the cloud is told about it with
    # MEISTER_OIDC_CA.
    services.kanidm = {
      # Pinned to a MAJOR, because kanidm's database is upgraded one major at
      # a time and `kanidmd domain upgrade-check` is a thing an operator runs
      # before moving: an unpinned `pkgs.kanidm` would move this box's
      # directory when nixpkgs moves. 1.10 is the newest that nixpkgs does not
      # mark end-of-life.
      #
      # `WithSecretProvisioning` is the same kanidm with the patches that let
      # a provisioning run set the idm_admin password and an oauth2 basic
      # secret from a FILE. Without them the only road to those two is an
      # interactive `kanidmd recover-account`, and a first boot cannot take an
      # interactive road.
      package = pkgs.kanidmWithSecretProvisioning_1_10;
      enableServer = true;
      serverSettings = {
        domain = cfg.fqdn;
        inherit origin;
        bindaddress = "0.0.0.0:8443";
        # NOT the files in /opt/meisterstack/pki directly, and the reason is
        # a property of the whole fleet rather than of kanidm: a private key
        # there is `meister:meister 0600` — `pki::pem::check_permissions`
        # refuses ANY group or other bit on one, so there is no mode that
        # would let a second service read it. kanidm runs as `kanidm` and got
        #
        #   Failed to configure TLS acceptor | The Private Key could not be
        #   parsed Io(Os { code: 13, kind: PermissionDenied })
        #
        # systemd's credentials are the way through: it opens the file as
        # root before the sandbox exists and hands the unit a 0400 copy of
        # its own. The path below is where it lands, and it is fixed.
        tls_chain = "/run/credentials/kanidm.service/tls-chain";
        tls_key = "/run/credentials/kanidm.service/tls-key";
        # No db_path: the module owns it (read-only, StateDirectory=kanidm),
        # and the bind mount above is what puts /var/lib/kanidm on the block.
        # A lab box has no second machine to back up to, and an online backup
        # that nobody restores is a directory that fills a disk.
        online_backup.enabled = false;
      };

      # Declarative, so that "who exists" is a diff and not a session with an
      # admin shell. What it cannot do is set a person's password — kanidm has
      # no api for writing one — so each account is finished once with
      # `kanidm person credential create-reset-token <name>`, and the report
      # says so.
      provision = {
        enable = true;
        # localhost, on purpose: the provisioner runs ON this box, and asking
        # it to resolve and trust the fqdn would make the first boot depend on
        # dns and on a trust store neither of which it needs.
        instanceUrl = "https://localhost:8443";
        acceptInvalidCerts = true;
        # Again the credential and not the file: the module folds the whole
        # first-boot into kanidm.service's ExecStartPost, which runs as
        # `kanidm` and read `/opt/meisterstack/pki/addons-admin: Permission
        # denied` — after the daemon had already said "ready to rock". A
        # post-start that fails takes the unit with it, so the box had a
        # working identity provider and a failed unit at the same time.
        idmAdminPasswordFile = "/run/credentials/kanidm.service/idm-admin";

        groups = {
          # The four roles this stack knows. The group in a token is
          # LABELLING and not a permission — the User object at the cloud is
          # what anything consults — but a directory that cannot express the
          # roles cannot be read by a human either.
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
            # BCP 212: a native application redirects to a server it runs on
            # the user's own machine. Kanidm allows that only on a public
            # client, and a public client enforces PKCE — which is what the
            # cli does anyway.
            public = true;
            enableLocalhostRedirects = true;
            originUrl = "http://localhost:8400/callback";
            originLanding = origin;
            # `preferred_username` = the short name, not the spn
            # (name@domain). The cloud looks a User up by this string, and a
            # directory entry is not found under an spn.
            preferShortUsername = true;
            scopeMaps.meister-viewers = [ "openid" "profile" "email" ];
            scopeMaps.meister-members = [ "openid" "profile" "email" ];
            scopeMaps.meister-operators = [ "openid" "profile" "email" ];
            scopeMaps.meister-admins = [ "openid" "profile" "email" ];
          };
          grafana = {
            displayName = "Grafana";
            # The third file this unit's post-start reads as `kanidm`, and
            # therefore the third credential: kanidm-provision writes this
            # client's basic secret, and it died on
            # `failed to read ".../addons-grafana-secret": Permission denied`
            # AFTER it had already recovered idm_admin and started creating
            # groups. Grafana reads the same secret at the other end, out of
            # a credential of its own.
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

    # --- the object store --------------------------------------------------
    #
    # Single node, replication 1: this is the backend images are fetched from
    # and snapshots will be exported to, not a resource this api serves.
    services.garage = {
      # Without it the module builds a unit with no ExecStart at all, and
      # systemd answers `garage.service: Service has no ExecStart=,
      # ExecStop=, or SuccessAction=. Refusing.` — which reads like a broken
      # unit rather than like a service nobody switched on. The other five
      # say `enable = true`; this one was the odd one out.
      enable = true;
      package = pkgs.garage_2;
      # rpc_secret and admin_token come from the environment file, because
      # both are secrets and the settings below are a store path.
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

    # --- metrics -----------------------------------------------------------
    #
    # One target per node AND role. The lab scraped nothing at all for a
    # while, and the observability report's finding was that the job simply
    # was not there; from a plan it cannot be missing.
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

    # --- logs --------------------------------------------------------------
    #
    # Single binary, filesystem storage. What arrives here is the WHOLE
    # journal of every node (nix/observability.nix), because every incident
    # this lab has had was diagnosed next to our lines rather than in them.
    services.loki = {
      enable = true;
      configuration = {
        auth_enabled = false;
        server.http_listen_port = 3100;
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

    # --- traces ------------------------------------------------------------
    #
    # OTLP over grpc, straight from the three binaries. Not through the
    # collector: it would be a process that can be down between a trace and
    # its store, and it would buy nothing at this size.
    services.tempo = {
      enable = true;
      settings = {
        server = {
          http_listen_port = 3200;
          grpc_listen_port = 9095;
        };
        distributor.receivers.otlp.protocols = {
          grpc.endpoint = "0.0.0.0:4317";
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

    # --- the window --------------------------------------------------------
    services.grafana = {
      enable = true;
      settings = {
        server = {
          http_addr = "0.0.0.0";
          # 3080 and not grafana's own 3000, because on the box this role was
          # written for the cloud-controller's REST api already has 3000
          # (nix/controllers.nix, and it is the port every cli profile and
          # every recipe in this repo names). Two listeners on one port is a
          # unit that fails to start, and the one that has to move is the one
          # whose port nothing else was written down against.
          http_port = 3080;
          root_url = "http://${cfg.fqdn}:3080/";
        };
        database.type = "sqlite3";
        # The local admin stays as the way back in when the identity provider
        # is the thing that is broken.
        security.admin_user = "admin";
        "auth.generic_oauth" = {
          enabled = true;
          name = "MeisterStack";
          client_id = "grafana";
          # Grafana reads a file rather than a value, so the secret stays out
          # of the store here too — and it reads it AS `grafana`, which is
          # why the file it is pointed at is systemd's own copy and not the
          # 0600 root-owned one in /opt/meisterstack/pki. Same reasoning as
          # kanidm's tls_key above; measured the same way ("got error while
          # expanding auth.generic_oauth.client_secret ... permission denied").
          client_secret = "$__file{/run/credentials/grafana.service/oauth-secret}";
          scopes = "openid profile email";
          auth_url = "${origin}/ui/oauth2";
          token_url = "${origin}/oauth2/token";
          api_url = "${origin}/oauth2/openid/grafana/userinfo";
          use_pkce = true;
          # The lab CA signs this Kanidm, and a public root list does not
          # contain it. tls_client_ca is where grafana takes ours from.
          tls_client_ca = "${pki}/ca.crt";
          # From the claim map above, so that a viewer in the directory is a
          # viewer here — rather than the "everybody is Admin" the k3s
          # instance ran with.
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
            url = "http://127.0.0.1:3100";
            jsonData.derivedFields = [{
              # `span_trace_id` and NOT `trace_id`: the id hangs on the span,
              # and Loki's `| json` flattens with an underscore. Found in the
              # lab, written down in lab/LAB.md, and the single most annoying
              # character in this whole file.
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

    # `kanidm` on the box, for the one thing provisioning cannot do: give a
    # person a password. `kanidm person credential create-reset-token alice`
    # prints a link, and that is how each of the four accounts is finished.
    environment.systemPackages = [ pkgs.kanidm_1_10 ];
  };
}
