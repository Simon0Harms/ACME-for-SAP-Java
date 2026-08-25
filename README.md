# sap_java_cert_renew.sh

Deploy ACME (or any PEM) certificates onto a **SAP AS Java** (NetWeaver Java)
instance — the ICM HTTPS server certificate and, optionally, Key Storage views
— from a single POSIX shell script that runs unchanged on Linux and AIX.

Written to be used as the `--reloadcmd` of
[acme.sh](https://github.com/acmesh-official/acme.sh), but it works just as well
from cron or by hand. It is the AS-Java companion to
[ACME-for-SAP-ABAP](https://github.com/Simon0Harms/ACME-for-SAP-ABAP).

> **Why a separate tool?** On the AS Java the SSL key pairs are not flat PSE
> files like on the ABAP stack — they live in **Key Storage views inside the
> database**. There is no supported `import_p12`-style OS command for those
> views. The clean, fully scriptable path is the ICM's `CRED=` PSE for the HTTPS
> server certificate; the DB-backed views are reachable only through the AS Java
> telnet administration console. This script handles both.

## What it does

1. Finds the newest server leaf certificate in the acme.sh data directory.
2. Works out the root CA for the chain (explicit path, `root_ca.cer` next to the
   leaf, or a system trust store) and builds a PKCS#12.
3. Imports it into the instance's `SAPSSLS.pse` (the file the ICM reads via
   `icm/ssl_config_* CRED=`), creates the SSO credentials, and reloads the ICM
   with `SIGHUP` — no restart, no downtime.
4. **Optionally** loads a client identity and/or the `service_ssl` view into the
   Key Storage via the telnet console (`KEYSTORE` command group), taking a full
   keystore `BACKUP` first and verifying with `LIST` afterwards.
5. Reports the outcome to a Checkmk spool file and optionally by mail.

It tracks each target independently and skips whatever has not changed, so a
long-lived client certificate is not re-loaded on every (short-lived) server
renewal. `FORCE=1` overrides.

## Repository layout

```
sap_java_cert_renew.sh            the script (POSIX sh, Linux + AIX)
sap_java_cert_renew.conf.example  example configuration
push-java.conf.example            example config for the central-push add-on
.gitignore                        keeps real config and key material out of the repo
LICENSE
README.md
```

## Requirements

- POSIX `/bin/sh` (dash, or ksh88 on AIX), `openssl`, `perl`, `awk`, `sed`,
  and a `telnet` client (only if you enable a view target).
- The SAP kernel tool `sapgenpse` in the instance's `exe` directory (server
  target).
- Run as a user that may write the instance `sec` directory and signal `icman`
  (typically `<sid>adm` or `root`).
- The AS Java telnet console reachable on `localhost:5<NR>08` (view targets).

Verified on AIX (`/bin/sh` = ksh88) and Linux (`/bin/sh` = dash / bash in POSIX
mode). The script deliberately avoids bash/ksh-only constructs and GNU-only
options, so it passes `sh -n`, `dash -n`, `bash --posix -n` and `shellcheck`.

## Configuration

Copy the example and edit it:

```sh
cp sap_java_cert_renew.conf.example sap_java_cert_renew.conf
$EDITOR sap_java_cert_renew.conf
chmod 600 sap_java_cert_renew.conf
```

The script sources `sap_java_cert_renew.conf` from its own directory if present.
Every setting can also be given as an environment variable, which is handy for
one-off overrides such as `DRYRUN=1` or `FORCE=1`.

The **SID is auto-detected** on single-system hosts (and wherever only one
system owns the `INSTANCE_NAME` directory, so a Diagnostics Agent alongside is
ignored). Set `SID` explicitly only when detection cannot decide. The FQDN is
read from the SAP instance profile (`SAPLOCALHOSTFULL`), so the OS host name can
stay the short name as SAP expects.

## Usage

Preview first — nothing is changed:

```sh
DRYRUN=1 ./sap_java_cert_renew.sh
```

As the acme.sh reload command:

```sh
acme.sh --issue -d sapjava.example.com \
  --reloadcmd /opt/sap/sap_java_cert_renew.sh
```

Or from cron / by hand. When nothing has changed the script exits quietly.

## The two mechanisms

| Target | Mechanism | Notes |
|---|---|---|
| **Server** (inbound HTTPS) | `sapgenpse` → `SAPSSLS.pse` → `SIGHUP` icman | Fully scriptable. By default (`SYNC_SERVER_VIEW=1`) the cert is also pushed into the NWA view so it doesn't drift; the view name is auto-detected (`ICM_SSL_<instance_id>_<port>`). Needs the telnet console configured; skipped gracefully otherwise. |
| **Client** identity | telnet `KEYSTORE LOAD` into a DB view | Needs a real **clientAuth** p12 (`CLIENT_P12`). A serverAuth-only ACME cert cannot be a client identity. Off by default. |
| **service_ssl** | telnet `KEYSTORE LOAD` | Legacy view; enable only if your system still uses it. |

`P4` on a stock instance is usually plain (no `SSLCONFIG`) — there is nothing to
renew there unless P4S is configured.

## Open validation points

The telnet `KEYSTORE` behaviour is not fully documented by SAP. **Test the view
targets on a non-production system first** and confirm:

- Whether `LOAD` overwrites an existing alias or needs a prior delete (the
  script takes a `BACKUP` before and runs `LIST` after so you can check). If your
  console needs an explicit delete, set `KEYSTORE_DELETE_CMD` to its delete
  command (run as `<cmd> <view> <alias>` before `LOAD`).
- Whether `LOAD` accepts the absolute staged path under `/usr/sap/<SID>/`.
- Whether the ICM reloads the `CRED` PSE on `SIGHUP` on your instance
  (otherwise use `RESTART_ICM_FALLBACK=1`).
- Switching the live endpoint between **RSA and ECC** is blocked by default
  (`ALLOW_ALGO_CHANGE=0`). Validate ECDSA end to end (Key Storage + IAIK-JSSE +
  CommonCryptoLib) before enabling it.

## Security notes

- The live `.conf` and all key material (`*.p12`, `*.pse`, `*.pw`, `*.key`,
  `*.pem`, ...) are git-ignored. Keep password files at `chmod 600`.
- Telnet passwords are piped through stdin (not visible in `ps`); staged p12
  files and command transcripts are securely removed after use, and the p12
  password is masked in `DRYRUN` output.
- The telnet console is expected to be bound to `localhost`.

## Central acme.sh host (optional)

Where acme.sh cannot run on the SAP host itself — no outbound access, no DNS API
credentials, AIX without a usable installation — run acme.sh on a central host
and let the add-on
[`sap_cert_push.sh`](https://github.com/Simon0Harms/ACME-for-SAP-ABAP/blob/main/sap_cert_push.sh)
(from the ABAP repo) copy the certificate over SSH and run this script on the
target:

```sh
acme.sh --issue -d sapjava.example.com \
  --reloadcmd "CONFIG_FILE=/srv/SSL/push-java.conf /srv/SSL/sap_cert_push.sh"
```

```sh
# /srv/SSL/push-java.conf
TARGETS="auto"
REMOTE_SCRIPT="/sap_migrate/skripte/Java/sap_java_cert_renew.sh"
SSH_USER="root"
```

The push script copies the leaf directory into `REMOTE_ACME_HOME` (default
`/root/.acme.sh`) and stages `root_ca.cer` next to the leaf, then runs
`sh REMOTE_SCRIPT` on the target. This script needs no special handling for that
mode: it finds the pushed leaf under `ACME_HOME` and auto-detects the SID.

Configure the target either through its own `sap_java_cert_renew.conf` (next to
the script or `/etc/sap_java_cert_renew.conf`) or by pushing environment from the
central host, e.g. `REMOTE_ENV="ALLOW_ALGO_CHANGE=1"` or
`REMOTE_ENV="CONFIG_FILE=/etc/sap_java_cert_renew.conf"`. See
`push-java.conf.example`.

## License

GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See
[LICENSE](LICENSE) or <https://www.gnu.org/licenses/gpl-3.0.html>.
