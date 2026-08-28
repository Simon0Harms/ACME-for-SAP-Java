#!/bin/sh
# =============================================================================
# sap_java_cert_renew.sh - deploy ACME/PEM certificates into a SAP AS Java stack
#
# Takes a certificate issued by acme.sh (or any PEM certificate plus key and
# chain) and deploys it to a SAP AS Java (NetWeaver Java) instance:
#   * ICM HTTPS server certificate -> SAPSSLS.pse referenced by icm/ssl_config_*
#     CRED=... (imported via sapgenpse, SSO credential created, ICM reloaded)
#   * optionally, Key Storage views (client identity / service_ssl) via the
#     AS Java telnet administration console (KEYSTORE command group, LOAD)
#
# Intended to be called as the acme.sh "reload command", e.g.
#   acme.sh --issue -d host.example.com --reloadcmd /opt/sap/sap_java_cert_renew.sh
# but it can also be run manually or from cron.
#
# -----------------------------------------------------------------------------
# WHY AS JAVA IS DIFFERENT (read before first use)
# -----------------------------------------------------------------------------
# On the AS Java the SSL key pairs are NOT stored as flat PSE files like on the
# ABAP stack / Host Agent, but as entries in Key Storage views inside the
# database. This script therefore uses TWO different mechanisms:
#
#   1) SERVER certificate (inbound HTTPS, ICM):
#      The ICM reads a PSE file via  icm/ssl_config_* ... CRED=.../SAPSSLS.pse
#      -> fully scriptable with sapgenpse: build p12 -> import_p12 -> seclogin
#         -> reload the ICM with SIGHUP. This is the default target.
#      -> CAVEAT: the matching NWA Key Storage view (ICM_SSL_<id>_<port>) will
#         still show the OLD certificate afterwards ("drift"). What the ICM
#         actually serves is the CRED PSE. Set SYNC_SERVER_VIEW=1 to also push
#         the certificate into the view via the telnet console.
#
#   2) CLIENT identity / service_ssl (and, optionally, the server view):
#      Pure DB-backed Key Storage views with no CRED file -> only reachable via
#      the AS Java telnet console (KEYSTORE command group, LOAD) on localhost.
#      -> LOAD requires that the p12 file lives under /usr/sap/<SID>/.
#      -> A HARICA/ACME server certificate has serverAuth EKU only and cannot be
#         used as a client identity; provide a proper clientAuth p12 (CLIENT_P12).
#
# -----------------------------------------------------------------------------
# OPEN VALIDATION POINTS (test on a non-production system first)
# -----------------------------------------------------------------------------
#   a) Does LOAD overwrite an existing alias, or is a prior DELETE/REMOVE
#      required? (not documented in the console's own 'man' output). The script
#      runs BACKUP before and LIST after each LOAD so you can verify the result.
#   b) Does LOAD accept the absolute path under /usr/sap/<SID>/ ? If the console
#      reports "file not found", try a path relative to the instance directory.
#   c) Does the ICM reload the CRED PSE on SIGHUP? (documented for OS-level PSEs;
#      verify on your instance, otherwise use RESTART_ICM_FALLBACK=1).
#   d) RSA <-> ECC: changing the algorithm of the LIVE endpoint is blocked by
#      default (ALLOW_ALGO_CHANGE). Validate ECDSA across the full AS Java path
#      (Key Storage + IAIK-JSSE + CommonCryptoLib) before enabling it.
#
# -----------------------------------------------------------------------------
# PORTABILITY
# -----------------------------------------------------------------------------
# Pure POSIX shell. Verified on:
#   * AIX    - /bin/sh is ksh88
#   * Linux  - /bin/sh is dash, or bash in POSIX mode
#
# Deliberately avoids bash/ksh-only constructs: no 'local', no 'typeset', no
# arrays or '+=', no 'mapfile', no process substitution, no 'trap ... ERR', no
# ${var,,}, no $RANDOM, no GNU-only options such as 'grep -m'. Lists are carried
# in the positional parameters ($@ / set --), which behaves identically in
# ksh88 and dash.
#
# Platform differences are wrapped in helper functions:
#   * sha256          - sha256sum, else 'openssl dgst -sha256'
#   * secure delete   - shred, else overwrite with dd (best effort)
#   * expiry math     - perl (GNU 'date -d' is not available on AIX)
#
# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
# Every setting can be overridden by an environment variable or by a config
# file. The config file is looked up in the same order as sap_cert_deploy.sh:
#   1. $CONFIG_FILE, if set in the environment
#   2. sap_java_cert_renew.conf next to this script
#   3. /etc/sap_java_cert_renew.conf
# The SID is auto-detected (see below), so no configuration is strictly
# required. Behavioural flags (DRYRUN, DO_CLIENT, ALLOW_ALGO_CHANGE, ...) can be
# set per run, e.g.  DRYRUN=1 ./sap_java_cert_renew.sh
#
# -----------------------------------------------------------------------------
# CENTRAL acme.sh HOST (optional)
# -----------------------------------------------------------------------------
# Where acme.sh cannot run on the SAP host itself, use the add-on
# sap_cert_push.sh (from the ACME-for-SAP-ABAP repository) on the central
# acme.sh host. It copies the renewed certificate over SSH and then runs this
# script there:
#   acme.sh ... --reloadcmd "CONFIG_FILE=/srv/SSL/push-java.conf /srv/SSL/sap_cert_push.sh"
# with, in push-java.conf:  TARGETS="auto"
#                           REMOTE_SCRIPT="/path/to/sap_java_cert_renew.sh"
#                           SSH_USER="root"
# See push-java.conf.example. This script needs no special handling for that
# mode: it finds the pushed leaf under ACME_HOME and auto-detects the SID.
#
# -----------------------------------------------------------------------------
# LICENSE
# -----------------------------------------------------------------------------
# GNU General Public License v3.0 or later. See the LICENSE file in the
# repository root, or <https://www.gnu.org/licenses/gpl-3.0.html>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
# =============================================================================

set -e

# --- config file: $CONFIG_FILE, else next to this script, else /etc -----------
# Same search order and variable name as sap_cert_deploy.sh, so the optional
# central-host add-on sap_cert_push.sh can point at a specific file via
# REMOTE_ENV="CONFIG_FILE=...". Sourced as shell code - keep it mode 0600.
if [ -z "${CONFIG_FILE:-}" ]; then
  _cfg_dir=$(dirname "$0" 2>/dev/null) || _cfg_dir="."
  case "$_cfg_dir" in
    /*) : ;;
    *)  _cfg_dir=$(cd "$_cfg_dir" 2>/dev/null && pwd) || _cfg_dir="." ;;
  esac
  if [ -f "$_cfg_dir/sap_java_cert_renew.conf" ]; then
    CONFIG_FILE="$_cfg_dir/sap_java_cert_renew.conf"
  else
    CONFIG_FILE="/etc/sap_java_cert_renew.conf"
  fi
fi
# shellcheck source=/dev/null
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

# ============================ Configuration ==================================
USR_SAP="${USR_SAP:-/usr/sap}"             # SAP base directory (rarely changed)
case "${INST:-}" in "") _INST_SET=0 ;; *) _INST_SET=1 ;; esac
INST="${INST:-00}"                         # instance number (two digits)
INSTANCE_NAME="${INSTANCE_NAME:-J00}"      # instance directory name, e.g. J00

# SID + instance: use configured/env values; otherwise auto-detect. Detection
# enumerates *Java* instances under $USR_SAP - a directory with a j2ee/ subdir,
# or a J<nr>/JC<nr> name - and ignores ABAP instances (DVEBMGS/D/ASCS/SCS/ERS
# without j2ee) and Diagnostics Agents (DAA / SMDA*). If exactly one Java
# instance owns INSTANCE_NAME it is used; else if there is exactly one Java
# instance overall, its SID and instance are used. On hosts with several Java
# systems (e.g. a Solution Manager landscape) set SID/INSTANCE_NAME explicitly.
_java_instances() {  # prints "SID INST" per Java instance
  for _d in "$USR_SAP"/*/; do
    _s=$(basename "$_d")
    case "$_s" in [A-Z][A-Z0-9][A-Z0-9]) ;; *) continue ;; esac
    case "$_s" in DAA) continue ;; esac
    for _i in "$USR_SAP/$_s"/*/; do
      [ -d "$_i" ] || continue
      _in=$(basename "$_i")
      case "$_in" in SMDA*) continue ;; esac
      if [ -d "$USR_SAP/$_s/$_in/j2ee" ]; then
        printf '%s %s\n' "$_s" "$_in"
      else
        case "$_in" in J[0-9][0-9]|JC[0-9][0-9]) printf '%s %s\n' "$_s" "$_in" ;; esac
      fi
    done
  done
}
_inst_num() { printf '%s' "$1" | sed -n 's/.*\([0-9][0-9]\)$/\1/p'; }  # trailing 2 digits

SID="${SID:-}"
JAVA_PAIRS=$(_java_instances 2>/dev/null)
if [ -z "$SID" ]; then
  _ji_match=$(printf '%s\n' "$JAVA_PAIRS" | awk -v i="$INSTANCE_NAME" 'NF && $2==i')
  if [ "$(printf '%s\n' "$_ji_match" | grep -c '[^[:space:]]')" = "1" ]; then
    SID=$(printf '%s\n' "$_ji_match" | awk 'NF{print $1; exit}')
  elif [ "$(printf '%s\n' "$JAVA_PAIRS" | grep -c '[^[:space:]]')" = "1" ]; then
    SID=$(printf '%s\n' "$JAVA_PAIRS" | awk 'NF{print $1; exit}')
    INSTANCE_NAME=$(printf '%s\n' "$JAVA_PAIRS" | awk 'NF{print $2; exit}')
  fi
elif [ ! -d "$USR_SAP/$SID/$INSTANCE_NAME" ]; then
  # SID given but the default instance dir is absent -> take the Java instance of that SID
  _ji_cand=$(printf '%s\n' "$JAVA_PAIRS" | awk -v s="$SID" 'NF && $1==s{print $2; exit}')
  [ -n "$_ji_cand" ] && INSTANCE_NAME="$_ji_cand"
fi
# derive the instance number from the (possibly detected) instance name unless set
if [ "$_INST_SET" = "0" ]; then
  _n=$(_inst_num "$INSTANCE_NAME"); [ -n "$_n" ] && INST="$_n"
fi

# Resolve the FQDN authoritatively from the SAP instance profile
# (SAPLOCALHOSTFULL / icm/host_name_full). The OS host name deliberately stays
# the short name (SAP convention, 13-character limit); 'hostname' on AIX often
# returns only the short name. Fallback: hostname / uname -n. Override with
# HOST_FQDN=... at any time.
_fqdn_from_profile() {
  _fp_dir="$USR_SAP/${SID}/SYS/profile"
  _fp_pre="${SID}_${INSTANCE_NAME}_"
  for _p in "$_fp_dir/$_fp_pre"*; do
    [ -f "$_p" ] || continue
    awk -F= '
      /^[ \t]*SAPLOCALHOSTFULL[ \t]*=/   { v=$2 }
      /^[ \t]*icm\/host_name_full[ \t]*=/{ if (v=="") v=$2 }
      END { gsub(/[ \t\r]/,"",v); if (v!="") print v }' "$_p"
    return 0
  done
}
HOST_FQDN="${HOST_FQDN:-$(_fqdn_from_profile 2>/dev/null)}"
[ -n "$HOST_FQDN" ] || HOST_FQDN=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)

ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
P12PW=changeit                             # transient, local only (openssl/sapgenpse/LOAD)

# Executables and SECUDIR of the Java instance
EXE="${EXE:-$USR_SAP/$SID/$INSTANCE_NAME/exe}"
INST_SEC="${INST_SEC:-$USR_SAP/$SID/$INSTANCE_NAME/sec}"

# External tools (on AIX possibly under /opt/freeware/bin/...)
OPENSSL="${OPENSSL:-openssl}"
PERL="${PERL:-perl}"

# Ports (default formulas: HTTPS = 5<NR>01, TELNET = 5<NR>08)
HTTPS_PORT="${HTTPS_PORT:-$(printf '5%s01' "$INST")}"
TELNET_HOST="${TELNET_HOST:-127.0.0.1}"
TELNET_PORT="${TELNET_PORT:-$(printf '5%s08' "$INST")}"

# CRED PSE the ICM serves on the HTTPS port: read it from the instance profile
# (the icm/ssl_config_<n> referenced by the HTTPS icm/server_port). This is the
# authoritative source; its file name (SAPSSLS.pse vs SAPSSLS_<port>.pse) also
# determines which Key Storage view to sync (see resolve_server_view).
_cred_pse_from_profile() {
  _cp_dir="$USR_SAP/${SID}/SYS/profile"
  _cp_pre="${SID}_${INSTANCE_NAME}_"
  for _p in "$_cp_dir/$_cp_pre"*; do
    [ -f "$_p" ] || continue
    case "$_p" in *.[0-9]|*.[0-9][0-9]) continue ;; esac   # skip rotated copies
    _cp_cfg=$(awk -v port="$HTTPS_PORT" '
      /^[ \t]*icm\/server_port_/ && /PROT=HTTPS/ && $0 ~ ("PORT=" port) {
        if (match($0,/SSLCONFIG=[A-Za-z0-9_]+/)) { print substr($0,RSTART+10,RLENGTH-10); exit } }' "$_p")
    [ -n "$_cp_cfg" ] || continue
    awk -v cfg="icm/$_cp_cfg" '
      $0 ~ ("^[ \t]*" cfg "[ \t]*=") {
        if (match($0,/CRED=[^, \t]+/)) { print substr($0,RSTART+5,RLENGTH-5); exit } }' "$_p"
    return 0
  done
}
ICM_CRED_PSE="${ICM_CRED_PSE:-$(_cred_pse_from_profile 2>/dev/null)}"
[ -n "$ICM_CRED_PSE" ] || ICM_CRED_PSE="$INST_SEC/SAPSSLS.pse"

# Staging directory for the telnet BACKUP/LOAD. The console only allows files
# under the Java INSTANCE installation directory (/usr/sap/<SID>/<INSTANCE>/),
# not /usr/sap/<SID>/SYS/... - so stage inside the instance's sec directory.
STAGE_DIR="${STAGE_DIR:-$USR_SAP/$SID/$INSTANCE_NAME/sec}"

# Telnet admin access (UME admin). Password from a protected file (chmod 600).
JAVA_TELNET_USER="${JAVA_TELNET_USER:-Administrator}"
JAVA_TELNET_PW_FILE="${JAVA_TELNET_PW_FILE:-/root/sap_certs/${SID}_telnet.pw}"
KEYSTORE_GROUP="${KEYSTORE_GROUP:-keystore}"   # telnet command group name
                                               # (verify with bare 'man' in the console)
# Telnet timing (POSIX piping is timing sensitive; raise these if LOADs fail)
TELNET_WAIT="${TELNET_WAIT:-2}"                # after connect / login
TELNET_STEP_WAIT="${TELNET_STEP_WAIT:-2}"      # between commands
TELNET_DEBUG="${TELNET_DEBUG:-0}"              # 1 = print the console transcript (p12 pw masked)
TELNET_EOL="${TELNET_EOL:-\n}"                 # line terminator piped to the console. Default \n
                                               # (the telnet client adds CR); if login still
                                               # fails try \r\n or \r.

# Key Storage view / entry names. The ICM_SSL views contain the instance id
# (e.g. ICM_SSL_39631_50001). SERVER_VIEW is auto-detected when left empty (from
# j2ee/instance_id + the HTTPS port, validated against LISTVIEWSNAMES). The
# client view is site specific; set it if DO_CLIENT=1.
SERVER_VIEW="${SERVER_VIEW:-}"                  # empty -> auto-detect ICM_SSL_<instid>_<port>
SERVER_ALIAS="${SERVER_ALIAS:-}"                # empty -> auto: existing FQDN entry, else ssl-credentials
CLIENT_VIEW="${CLIENT_VIEW:-}"                   # e.g. CLIENT_ICM_SSL_<instid>
CLIENT_ALIAS="${CLIENT_ALIAS:-}"                # EXACT existing entry name (from NWA)
SERVICE_SSL_VIEW="${SERVICE_SSL_VIEW:-service_ssl}"
SERVICE_SSL_ALIAS="${SERVICE_SSL_ALIAS:-ssl-credentials}"

# Optional: if LOAD does not overwrite an existing alias on your console, set the
# console's delete command here; it is then run as "<cmd> <view> <alias>" before
# LOAD. Empty = LOAD only (relies on overwrite). Verify the exact command/syntax
# with bare 'man' in the telnet console before enabling.
KEYSTORE_DELETE_CMD="${KEYSTORE_DELETE_CMD:-}"
KEYSTORE_BACKUP="${KEYSTORE_BACKUP:-0}"     # 1 = attempt a keystore BACKUP before LOAD.
                                            # Default 0: on AS Java 7.50 'BACKUP' expects an
                                            # existing file (restore/upload), so creating one
                                            # fails with "Backup not found". Failure is non-fatal.

# Which targets to process? (1 = yes, 0 = no)
DO_SERVER="${DO_SERVER:-1}"                 # ICM HTTPS server cert (CRED PSE)
DO_CLIENT="${DO_CLIENT:-0}"                 # client Key Storage view (telnet LOAD)
DO_SERVICE_SSL="${DO_SERVICE_SSL:-0}"       # legacy service_ssl (only if actually used)
SYNC_SERVER_VIEW="${SYNC_SERVER_VIEW:-1}"   # also push the server cert into the NWA view
                                            # (keeps NWA in sync; needs telnet configured)

# Behaviour
DRYRUN="${DRYRUN:-${DRY_RUN:-0}}"          # 1 = only print what would happen (DRY_RUN alias accepted)
ALLOW_ALGO_CHANGE="${ALLOW_ALGO_CHANGE:-0}" # 1 = allow an RSA<->ECC switch on the live endpoint
FORCE="${FORCE:-0}"                         # 1 = ignore the idempotency state
RESTART_ICM_FALLBACK="${RESTART_ICM_FALLBACK:-0}"  # 1 = restart the instance instead of SIGHUP

# Root CA for the server chain. Primary source is root_ca.cer next to the leaf;
# ROOT_CA_FILE overrides it explicitly. As a last resort the system trust store
# is scanned for a certificate whose subject contains ROOT_CA_SUBJECT_MATCH
# (only if that variable is set).
ROOT_CA_FILE="${ROOT_CA_FILE:-}"
ROOT_CA_SUBJECT_MATCH="${ROOT_CA_SUBJECT_MATCH:-}"

# External, long-lived client p12 (clientAuth) - NOT from acme.sh. It must
# contain the full chain; if it does not, point CLIENT_CHAIN at a PEM file with
# the intermediate/root certificates (they are then appended on repack).
CLIENT_P12="${CLIENT_P12:-/root/sap_certs/client.p12}"
CLIENT_P12PW_FILE="${CLIENT_P12PW_FILE:-/root/sap_certs/client.p12.pw}"
CLIENT_CHAIN="${CLIENT_CHAIN:-}"

# Checkmk / mail (both optional: no spool dir -> no Checkmk; no MAILTO -> no mail)
MAILTO="${MAILTO:-}"
CMK_SPOOL="${CMK_SPOOL:-/var/lib/check_mk_agent/spool}"
CMK_SVC="${CMK_SVC:-SAP Java Cert $SID}"
WARN_DAYS="${WARN_DAYS:-14}"
CRIT_DAYS="${CRIT_DAYS:-7}"

# Idempotency state (per-target fingerprints)
STATE_FILE="${STATE_FILE:-/var/lib/sap_cert_renew/java_${SID}.fp}"

# --- SID resolution check ----------------------------------------------------
if [ -z "$SID" ]; then
  echo "ERROR: could not determine the SAP SID automatically." >&2
  if printf '%s\n' "$JAVA_PAIRS" | grep -q '[^[:space:]]'; then
    echo "       Several Java instances found - set SID (and INSTANCE_NAME) to one of:" >&2
    printf '%s\n' "$JAVA_PAIRS" | awk 'NF{print "         SID="$1"  INSTANCE_NAME="$2}' >&2
  else
    echo "       No Java instance found under $USR_SAP." >&2
  fi
  echo "       Configure it in sap_java_cert_renew.conf (or /etc/sap_java_cert_renew.conf)." >&2
  exit 2
fi

# ============================================================================
OS=$(uname -s 2>/dev/null || echo unknown)
export SECUDIR="$INST_SEC"
case "$OS" in
  AIX) LIBPATH="$EXE${LIBPATH:+:$LIBPATH}"; export LIBPATH ;;
  *)   LD_LIBRARY_PATH="$EXE${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; export LD_LIBRARY_PATH ;;
esac

HOST_SHORT=$(printf '%s' "$HOST_FQDN" | cut -d. -f1)
SIDADM="$(printf '%s' "$SID" | tr '[:upper:]' '[:lower:]')adm"

FAILED=0; FAIL_MSG=""; STEP="init"
PRIV_TMP=""; TMP_P12=""
INSTANCE_UP="${INSTANCE_UP:-}"; DEFERRED=0
JAVA_TELNET_PW=""

have() { command -v "$1" >/dev/null 2>&1; }

log()  { printf '%s\n' "$*"; }
run()  {  # run a command - in DRYRUN only print it
  if [ "$DRYRUN" = "1" ]; then printf '  [DRYRUN] %s\n' "$*"; return 0; fi
  "$@"
}

report_checkmk() {  # $1=state $2=perf $3=text
  [ -d "$CMK_SPOOL" ] || return 0
  printf '<<<local>>>\n%s "%s" %s %s\n' "$1" "$CMK_SVC" "$2" "$3" \
    > "$CMK_SPOOL/sap_java_cert_$SID" 2>/dev/null || true
}

send_mail() {  # $1=subject $2=body
  [ -n "$MAILTO" ] || return 0
  MAIL_BIN=""
  if   have mailx; then MAIL_BIN="mailx"
  elif have mail;  then MAIL_BIN="mail"
  else return 0; fi
  printf '%s\n\nHost : %s\nSID  : %s\nTime : %s\n' "$2" "$HOST_FQDN" "$SID" \
    "$(date '+%Y-%m-%d %H:%M:%S')" \
    | "$MAIL_BIN" -s "[$HOST_SHORT] $1" "$MAILTO" 2>/dev/null || true
}

secure_rm() {
  for _sr_f in "$@"; do
    [ -e "$_sr_f" ] || continue
    if have shred; then shred -u "$_sr_f" 2>/dev/null && continue; fi
    _sr_sz=$(wc -c < "$_sr_f" 2>/dev/null || echo 0)
    case "$_sr_sz" in ''|*[!0-9]*) _sr_sz=0 ;; esac
    [ "$_sr_sz" -gt 0 ] && dd if=/dev/zero of="$_sr_f" bs=1024 \
      count=$(( _sr_sz / 1024 + 1 )) 2>/dev/null || true
    rm -f "$_sr_f" 2>/dev/null || true
  done
  return 0
}

sha256_of_file() {
  if have sha256sum; then sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  else "$OPENSSL" dgst -sha256 "$1" 2>/dev/null | sed 's/^.*= *//'; fi
}

days_left() {
  "$OPENSSL" x509 -in "$1" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' \
    | "$PERL" -MTime::Local -ne '
        my %m=(Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11);
        if (/(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d{4})/) {
          print int((Time::Local::timegm($5,$4,$3,$2,$m{$1},$6) - time)/86400);
        }' 2>/dev/null
}

die() { FAILED=1; FAIL_MSG="$1"; exit 1; }

make_priv_tmp() {
  _mt_base="${TMPDIR:-/tmp}"
  if have mktemp; then PRIV_TMP=$(mktemp -d "$_mt_base/sapjcert.XXXXXX" 2>/dev/null) || PRIV_TMP=""; fi
  if [ -z "$PRIV_TMP" ]; then
    _mt_rnd=$("$PERL" -e 'print int(rand(1000000000))' 2>/dev/null || echo "$$")
    PRIV_TMP="$_mt_base/sapjcert.$$.$_mt_rnd"
    ( umask 077; mkdir "$PRIV_TMP" ) || die "cannot create temp directory"
  fi
  chmod 700 "$PRIV_TMP" 2>/dev/null || true
}

cleanup() {
  _cu_rc=$?
  set +e
  [ -n "$TMP_P12" ] && secure_rm "$TMP_P12"
  [ -n "$PRIV_TMP" ] && [ -d "$PRIV_TMP" ] && rm -rf "$PRIV_TMP" 2>/dev/null
  # securely remove any staged p12 left in the (non-private) STAGE_DIR
  secure_rm "$STAGE_DIR"/acme_java_*.p12 2>/dev/null

  if [ "$FAILED" -ne 0 ] || [ "$_cu_rc" -ne 0 ]; then
    _cu_msg="$FAIL_MSG"; [ -n "$_cu_msg" ] || _cu_msg="aborted in step: ${STEP:-unknown} (rc=$_cu_rc)"
    echo "ERROR: $_cu_msg" >&2
    report_checkmk 2 "-" "AS Java certificate renewal FAILED: $_cu_msg"
    send_mail "CRIT: AS Java certificate $SID" "The renewal failed.

$_cu_msg"
    return
  fi
  _cu_days=$(days_left "${LEAF:-}")
  _cu_exp=$("$OPENSSL" x509 -in "${LEAF:-}" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  _cu_state=0
  if [ "$DEFERRED" = "1" ]; then
    report_checkmk 1 "-" "AS Java certificate staged in the PSE; instance was down - ICM reload/view sync deferred to the next run while up"
    return
  fi
  if [ -n "$_cu_days" ]; then
    [ "$_cu_days" -le "$WARN_DAYS" ] && _cu_state=1
    [ "$_cu_days" -le "$CRIT_DAYS" ] && _cu_state=2
    report_checkmk "$_cu_state" "days_left=$_cu_days;$WARN_DAYS;$CRIT_DAYS" \
      "AS Java certificate active, valid until $_cu_exp ($_cu_days days)"
  else
    report_checkmk 0 "-" "AS Java certificate processed"
  fi
}
trap cleanup EXIT

# ---- newest server leaf from acme.sh (directory WITHOUT 'clnt') -------------
newest_leaf() {
  set --
  for _nl_d in "$ACME_HOME"/*/; do
    [ -d "$_nl_d" ] || continue
    _nl_lc=$(basename "$_nl_d" | tr '[:upper:]' '[:lower:]')
    case "$_nl_lc" in *clnt*) continue ;; esac
    for _nl_f in "$_nl_d"*.cer; do
      [ -f "$_nl_f" ] || continue
      case "$_nl_f" in */ca.cer|*/fullchain.cer|*/root_ca.cer) continue ;; esac
      set -- "$@" "$_nl_f"
    done
  done
  [ "$#" -gt 0 ] || return 0
  ls -t "$@" 2>/dev/null | head -n 1
}

# ---- build a p12 from an acme.sh leaf ---------------------------------------
build_p12() {  # $1=leaf $2=out.p12 $3=root-PEM
  _bp_leaf="$1"; _bp_out="$2"; _bp_root="${3:-}"
  _bp_dir=$(dirname "$_bp_leaf"); _bp_key="${_bp_leaf%.cer}.key"; _bp_chain="$_bp_dir/ca.cer"
  _bp_tmpchain="$PRIV_TMP/chain.pem"
  [ -f "$_bp_leaf" ]  || { echo "build_p12: leaf missing"   >&2; return 1; }
  [ -f "$_bp_key" ]   || { echo "build_p12: key missing"    >&2; return 1; }
  [ -f "$_bp_chain" ] || { echo "build_p12: ca.cer missing" >&2; return 1; }
  if [ -n "$_bp_root" ] && [ -f "$_bp_root" ]; then
    { cat "$_bp_chain"; echo; cat "$_bp_root"; } > "$_bp_tmpchain" || { secure_rm "$_bp_tmpchain"; return 1; }
  else
    cp "$_bp_chain" "$_bp_tmpchain" || { secure_rm "$_bp_tmpchain"; return 1; }
  fi
  if "$OPENSSL" pkcs12 -export -inkey "$_bp_key" -in "$_bp_leaf" -certfile "$_bp_tmpchain" \
       -name "$(basename "$_bp_out" .p12)" -passout pass:"$P12PW" -out "$_bp_out"; then
    secure_rm "$_bp_tmpchain"; return 0
  fi
  secure_rm "$_bp_tmpchain"; return 1
}

# ---- public-key algorithm (RSA/EC/?) of a PEM certificate ------------------
key_algo_of_cert() {  # $1 = certificate file -> RSA|EC|?
  # awk instead of 'grep -m1' (the latter is GNU-only, absent on AIX)
  _ka=$("$OPENSSL" x509 -in "$1" -noout -text 2>/dev/null \
        | awk '/Public Key Algorithm/{print; exit}' | tr '[:upper:]' '[:lower:]')
  case "$_ka" in
    *rsa*) echo RSA ;;
    *ec*)  echo EC  ;;
    *)     echo '?' ;;
  esac
}

# ---- algorithm of the certificate currently served on HTTPS_PORT -----------
served_key_algo() {  # -> RSA|EC|?  (empty if the port is unreachable)
  _sk_tmp="$PRIV_TMP/served.pem"
  "$OPENSSL" s_client -connect "127.0.0.1:$HTTPS_PORT" -servername "$HOST_FQDN" \
       </dev/null 2>/dev/null \
    | "$OPENSSL" x509 -outform pem 2>/dev/null > "$_sk_tmp" || true
  if [ -s "$_sk_tmp" ]; then key_algo_of_cert "$_sk_tmp"; else printf ''; fi
  secure_rm "$_sk_tmp"
}

# ---- algorithm of the current CRED PSE's own cert (offline, when down) ------
pse_key_algo() {  # -> RSA|EC|?  (empty if unreadable)
  [ -f "$ICM_CRED_PSE" ] || { printf ''; return 0; }
  _pk_tmp="$PRIV_TMP/cur_pse.crt"
  if "$EXE/sapgenpse" export_own_cert -p "$ICM_CRED_PSE" -x "" -o "$_pk_tmp" >/dev/null 2>&1 \
     && [ -s "$_pk_tmp" ]; then
    key_algo_of_cert "$_pk_tmp"
  else
    printf ''
  fi
  secure_rm "$_pk_tmp"
}

# ---- algorithm-change guard ------------------------------------------------
# Prefers the live endpoint; if that is unreachable (instance down) it falls
# back to the current CRED PSE so the guard still works offline.
algo_guard() {  # $1 = new leaf
  _ag_new=$(key_algo_of_cert "$1")
  _ag_cur=$(served_key_algo); _ag_src="served"
  if [ -z "$_ag_cur" ]; then _ag_cur=$(pse_key_algo); _ag_src="current PSE"; fi
  if [ -n "$_ag_cur" ]; then
    log "Algorithm: current='$_ag_cur' (from $_ag_src), new='$_ag_new'"
  else
    log "Algorithm: current=unknown (endpoint down and PSE unreadable) - guard inactive, new='$_ag_new'"
  fi
  if [ -n "$_ag_cur" ] && [ "$_ag_cur" != "?" ] && [ "$_ag_new" != "?" ] \
     && [ "$_ag_cur" != "$_ag_new" ]; then
    if [ "$ALLOW_ALGO_CHANGE" = "1" ]; then
      log "WARN: algorithm change $_ag_cur -> $_ag_new allowed (ALLOW_ALGO_CHANGE=1)."
    elif [ "$DRYRUN" = "1" ]; then
      log "WARN: algorithm change $_ag_cur -> $_ag_new detected."
      log "      A real run would BLOCK here (ALLOW_ALGO_CHANGE=0)."
      log "      Validate ECDSA support on non-production first, then set ALLOW_ALGO_CHANGE=1."
    else
      die "algorithm change $_ag_cur -> $_ag_new detected. Blocked on production. \
Validate ECDSA support on this box first, then set ALLOW_ALGO_CHANGE=1."
    fi
  fi
  return 0
}

# ========================= telnet KEYSTORE harness ==========================
# POSIX-only (no 'expect'). Login and commands are piped into the telnet client
# stdin with sleeps. If commands are executed unreliably, raise TELNET_WAIT.
# File-free: commands come in as a newline-separated string, the transcript is
# printed to stdout (captured by the caller) - no temp files, and the password
# goes through stdin, never argv or disk.
java_telnet() {  # $1 = commands (newline-separated); prints transcript to stdout
  if ! have telnet; then echo "java_telnet: 'telnet' not found" >&2; return 1; fi
  if [ -z "$JAVA_TELNET_PW" ]; then
    echo "java_telnet: telnet password is empty ($JAVA_TELNET_PW_FILE, chmod 600)" >&2; return 1
  fi
  {
    sleep "$TELNET_WAIT"
    printf '%s%b' "$JAVA_TELNET_USER" "$TELNET_EOL"; sleep "$TELNET_WAIT"
    printf '%s%b' "$JAVA_TELNET_PW"   "$TELNET_EOL"; sleep "$TELNET_WAIT"
    printf 'add %s%b' "$KEYSTORE_GROUP" "$TELNET_EOL"; sleep "$TELNET_STEP_WAIT"
    printf '%s\n' "$1" | while IFS= read -r _jt_line; do
      printf '%s%b' "$_jt_line" "$TELNET_EOL"; sleep "$TELNET_STEP_WAIT"
    done
    printf 'exit%b' "$TELNET_EOL"; sleep "$TELNET_WAIT"
  } | telnet "$TELNET_HOST" "$TELNET_PORT" 2>&1
  return 0
}

# ---- stage a p12 under the instance dir (LOAD restriction) -----------------
stage_p12() {  # $1=source.p12 $2=target-name -> full path on stdout
  mkdir -p "$STAGE_DIR" 2>/dev/null || { echo "" ; return 1; }
  _sp_dst="$STAGE_DIR/$2"
  cp -p "$1" "$_sp_dst" 2>/dev/null || { echo ""; return 1; }
  # the console reads the file as the Java process user (<sid>adm); make it
  # readable via the sapsys group (best effort chown; group-read is enough)
  chown "$SIDADM":sapsys "$_sp_dst" 2>/dev/null || true
  chmod 640 "$_sp_dst" 2>/dev/null || true
  printf '%s' "$_sp_dst"
}

# ---- read j2ee/instance_id from the instance profile -----------------------
_instid_from_profile() {  # -> digits of j2ee/instance_id (e.g. 39631)
  _ip_dir="$USR_SAP/${SID}/SYS/profile"
  _ip_pre="${SID}_${INSTANCE_NAME}_"
  for _p in "$_ip_dir/$_ip_pre"*; do
    [ -f "$_p" ] || continue
    awk -F= '/^[ \t]*j2ee\/instance_id[ \t]*=/ {
               gsub(/[^0-9]/,"",$2); if ($2!="") { print $2; exit } }' "$_p"
    return 0
  done
}

# ---- list Key Storage view names via the telnet console (LISTVIEWSNAMES) ----
keystore_views() {  # -> one view name per line (best effort; never fatal)
  [ "$DRYRUN" = "1" ] && return 0
  have telnet || return 0
  [ -n "$JAVA_TELNET_PW" ] || return 0
  _kv_out=$(java_telnet "LISTVIEWSNAMES") || return 0
  # keep only bare token lines (view names are [A-Za-z0-9_]); drops banner/prompts
  printf '%s\n' "$_kv_out" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -E '^[A-Za-z0-9_]+$'
}

# ---- resolve the server view from the CRED PSE the ICM actually serves ------
# The relevant view is the one whose pse_location is the ICM's CRED PSE. That
# mapping follows the PSE file name:
#   SAPSSLS.pse         -> ICM_SSL_<instid>
#   SAPSSLS_<port>.pse  -> ICM_SSL_<instid>_<port>
# We derive that name, then validate against LISTVIEWSNAMES (with fallbacks).
resolve_server_view() {  # -> view name (best effort) or empty; never fatal
  _rsv_id=$(_instid_from_profile 2>/dev/null)
  [ -n "$_rsv_id" ] || return 0
  _rsv_cred=$(basename "${ICM_CRED_PSE:-}" 2>/dev/null)
  case "$_rsv_cred" in
    SAPSSLS_*.pse) _sfx=${_rsv_cred#SAPSSLS_}; _sfx=${_sfx%.pse}; _rsv_primary="ICM_SSL_${_rsv_id}_${_sfx}" ;;
    *)             _rsv_primary="ICM_SSL_${_rsv_id}" ;;
  esac
  _rsv_alt="ICM_SSL_${_rsv_id}_${HTTPS_PORT}"   # port-based guess
  _rsv_base="ICM_SSL_${_rsv_id}"                # base view
  # no live validation possible -> return the best-guess (CRED-derived) name
  if [ "$DRYRUN" = "1" ] || ! have telnet || [ -z "$JAVA_TELNET_PW" ]; then
    printf '%s' "$_rsv_primary"; return 0
  fi
  _rsv_views=$(keystore_views 2>/dev/null) || _rsv_views=""
  for _c in "$_rsv_primary" "$_rsv_alt" "$_rsv_base"; do
    if printf '%s\n' "$_rsv_views" | grep -Fxq "$_c"; then printf '%s' "$_c"; return 0; fi
  done
  printf '%s' "$_rsv_primary"
}

# ---- renew one Key Storage view via telnet ---------------------------------
# $2 is a preference-ordered, space-separated list of candidate entry aliases.
# The target is the first candidate that already exists in the view (so an
# existing FQDN-named key is reused rather than a second entry created); if none
# exist, the first candidate is used. All existing candidates are deleted before
# LOAD (needs KEYSTORE_DELETE_CMD) so exactly one entry remains - no duplicates.
load_view() {  # $1=view $2=alias-candidates(pref order) $3=source.p12 $4=password(opt) -> rc
  _lv_view="$1"; _lv_cands="$2"; _lv_src="$3"; _lv_pw="${4:-$P12PW}"
  if [ -z "$_lv_view" ] || [ -z "$_lv_cands" ]; then
    echo "load_view: view or alias not configured - skipped"; return 1
  fi
  _lv_ts=$(date +%Y%m%d%H%M%S)
  _lv_bak="$STAGE_DIR/keystore_backup_${_lv_ts}.bak"
  _lv_stage_name="acme_java_${_lv_view}_${_lv_ts}.p12"

  # DRYRUN: preview (can't LIST) -> assume the first candidate is the target
  if [ "$DRYRUN" = "1" ]; then
    for _c in $_lv_cands; do _lv_alias="$_c"; break; done
    log "View '$_lv_view': (DRYRUN) LOAD (alias '$_lv_alias', from candidates: $_lv_cands) -> LIST"
    printf '  [DRYRUN] telnet %s %s -- login as %s, add %s, then:\n' \
      "$TELNET_HOST" "$TELNET_PORT" "$JAVA_TELNET_USER" "$KEYSTORE_GROUP"
    [ "$KEYSTORE_BACKUP" = "1" ] && printf '    | BACKUP %s   (best effort)\n' "$_lv_bak"
    [ -n "$KEYSTORE_DELETE_CMD" ] && printf '    | %s %s <stray candidate>   (only differently-named extras, if any)\n' "$KEYSTORE_DELETE_CMD" "$_lv_view"
    printf '    | LOAD %s %s -PKCS12 %s ********   (overwrites the entry of that name)\n' "$_lv_view" "$_lv_alias" "$STAGE_DIR/$_lv_stage_name"
    printf '    | LIST %s\n' "$_lv_view"
    return 0
  fi

  _lv_stage=$(stage_p12 "$_lv_src" "$_lv_stage_name") || _lv_stage=""
  [ -n "$_lv_stage" ] || { echo "load_view: staging failed ($STAGE_DIR)"; return 1; }

  # optional keystore backup, in its own session so its outcome does not mask the
  # LOAD verification (the backup is a safety net; the served cert is the PSE)
  if [ "$KEYSTORE_BACKUP" = "1" ]; then
    _lv_bkout=$(java_telnet "BACKUP $_lv_bak")
    [ "$TELNET_DEBUG" = "1" ] && printf '%s\n' "$_lv_bkout" | sed 's/^/    bk> /'
    if printf '%s\n' "$_lv_bkout" | grep -qi -e error -e 'not found' -e prohibited -e 'usage:' -e failed; then
      echo "WARN: keystore BACKUP failed (non-fatal) - continuing with LOAD. Set KEYSTORE_BACKUP=0 to skip it."
    fi
  fi

  # one pre-LIST: which candidates already exist -> pick target + deletes
  _lv_present=""
  if have telnet && [ -n "$JAVA_TELNET_PW" ]; then
    _lv_listing=$(java_telnet "LIST $_lv_view" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    for _c in $_lv_cands; do
      printf '%s\n' "$_lv_listing" | grep -Fxq "$_c" && _lv_present="$_lv_present $_c"
    done
  fi
  # target = first existing candidate, else the first candidate
  _lv_alias=""
  for _c in $_lv_present; do _lv_alias="$_c"; break; done
  if [ -z "$_lv_alias" ]; then for _c in $_lv_cands; do _lv_alias="$_c"; break; done; fi

  # LOAD overwrites an entry of the SAME alias, so the target itself needs no
  # delete. Only *other* existing candidates (differently-named stray keys from a
  # previous run or manual import) would remain as extra entries - remove those
  # if a delete command is available; otherwise just warn.
  _lv_dels=""
  for _c in $_lv_present; do
    [ "$_c" = "$_lv_alias" ] && continue
    if [ -n "$KEYSTORE_DELETE_CMD" ]; then
      _lv_dels="$_lv_dels $_c"
      log "View '$_lv_view': removing stray entry '$_c'"
    else
      echo "WARN: stray key entry '$_c' remains in '$_lv_view' (LOAD updates '$_lv_alias' only)."
      echo "      Set KEYSTORE_DELETE_CMD=DELETE to remove such extra entries automatically."
    fi
  done

  # deletes (if any) then LOAD then LIST - verified on its own output
  _lv_cmds=$(
    for _a in $_lv_dels; do printf '%s %s %s\n' "$KEYSTORE_DELETE_CMD" "$_lv_view" "$_a"; done
    printf 'LOAD %s %s -PKCS12 %s %s\n' "$_lv_view" "$_lv_alias" "$_lv_stage" "$_lv_pw"
    printf 'LIST %s\n' "$_lv_view"
  )

  log "View '$_lv_view': LOAD (alias '$_lv_alias') -> LIST"
  _lv_out=$(java_telnet "$_lv_cmds") || { secure_rm "$_lv_stage"; return 1; }

  # optional: show the raw console transcript for diagnosis (passwords masked)
  if [ "$TELNET_DEBUG" = "1" ]; then
    printf '%s\n' "$_lv_out" \
      | awk -v pw="$JAVA_TELNET_PW" '{l=$0;sub(/\r$/,"",l); if(pw!=""&&l==pw){print "********";next} if($0~/-PKCS12/){$NF="********"} print}' \
      | sed 's/^/    tn> /'
  fi

  _lv_rc=0
  # telnet login failure -> precise, actionable message (not the generic one below)
  if printf '%s\n' "$_lv_out" | grep -qi -e 'login failed' -e 'authentication failed' -e 'cannot authenticate'; then
    echo "WARN: telnet login failed for user '$JAVA_TELNET_USER' on $TELNET_HOST:$TELNET_PORT."
    echo "      Check JAVA_TELNET_USER and the password in $JAVA_TELNET_PW_FILE"
    echo "      (test it manually: telnet $TELNET_HOST $TELNET_PORT). The server certificate"
    echo "      is deployed via the CRED PSE regardless; only the NWA view sync is affected."
    secure_rm "$_lv_stage"; return 1
  fi
  # verification: no LOAD error, and the target alias present in the LIST output
  if printf '%s\n' "$_lv_out" | grep -qi -e 'error' -e 'exception' -e 'not found' -e 'no such' -e 'prohibited' -e 'usage:' -e 'failed'; then
    echo "WARN: LOAD reported an error for view '$_lv_view' (run with TELNET_DEBUG=1 to see it):"
    printf '%s\n' "$_lv_out" | grep -i -e error -e exception -e 'not found' -e 'no such' -e prohibited -e 'usage:' -e failed \
      | awk -v pw="$JAVA_TELNET_PW" '{l=$0;sub(/\r$/,"",l); if(pw!=""&&l==pw){print "********";next} if($0~/-PKCS12/){$NF="********"} print}' \
      | sed 's/^/    > /' | head -n 5
    _lv_rc=1
  fi
  if ! printf '%s\n' "$_lv_out" | grep -q "$_lv_alias"; then
    echo "WARN: alias '$_lv_alias' not found in LIST of '$_lv_view' after LOAD (run with TELNET_DEBUG=1 to inspect)."
    _lv_rc=1
  fi
  secure_rm "$_lv_stage"
  return $_lv_rc
}

# ---- server certificate via the ICM CRED PSE -------------------------------
renew_icm_server() {  # $1 = p12 (with chain + root)
  _ri_p12="$1"
  [ -d "$INST_SEC" ] || { echo "WARN: SECUDIR $INST_SEC missing - server skipped"; return 1; }
  log "ICM server: updating CRED PSE $ICM_CRED_PSE"

  if [ -f "$ICM_CRED_PSE" ]; then
    run cp -p "$ICM_CRED_PSE" "$ICM_CRED_PSE.$(date +%Y%m%d%H%M%S).bak"
    run rm -f "$ICM_CRED_PSE"
  fi
  run rm -f "$INST_SEC/cred_v2"
  run "$EXE/sapgenpse" import_p12 -p "$ICM_CRED_PSE" -x "" -z "$P12PW" "$_ri_p12"
  run "$EXE/sapgenpse" seclogin   -p "$ICM_CRED_PSE" -x "" -O "$SIDADM"
  run chown "$SIDADM":sapsys "$ICM_CRED_PSE" "$INST_SEC/cred_v2"
  run chmod 600            "$ICM_CRED_PSE" "$INST_SEC/cred_v2"
  reload_icm
  return 0
}

# ---- is this instance running? ---------------------------------------------
# Proxy: an icman / jstart / jlaunch process referencing this instance's profile
# or directory. Override by presetting INSTANCE_UP=1|0 in the environment.
instance_running() {
  _ir_prof="${SID}_${INSTANCE_NAME}_"
  ps -eo args 2>/dev/null | grep -v grep \
    | grep -E "(icman|jstart|jlaunch)" | grep -q "$_ir_prof" && return 0
  ps -eo args 2>/dev/null | grep -v grep | grep -q "$USR_SAP/$SID/$INSTANCE_NAME/" && return 0
  return 1
}

# ---- reload the ICM (SIGHUP to the instance's icman; fallback: restart) -----
reload_icm() {
  if [ "$INSTANCE_UP" = "0" ]; then
    log "Instance is down - ICM reload skipped; the new certificate is staged in the"
    log "PSE and will be served automatically the next time the instance starts."
    return 0
  fi
  if [ "$RESTART_ICM_FALLBACK" = "1" ]; then
    log "ICM reload: fallback -> sapcontrol RestartInstance (downtime!)"
    run sapcontrol -nr "$INST" -function RestartInstance
    return 0
  fi
  # identify the icman process of this instance via the profile name
  _rc_prof="${SID}_${INSTANCE_NAME}_"
  _rc_pids=$(ps -eo pid,args 2>/dev/null | grep icman | grep "$_rc_prof" | grep -v grep | awk '{print $1}')
  if [ -z "$_rc_pids" ]; then
    echo "WARN: no icman found for $_rc_prof - ICM NOT reloaded."
    echo "      The new server certificate is served only after an ICM reload/restart."
    return 1
  fi
  for _rc_p in $_rc_pids; do
    log "ICM reload: SIGHUP to icman PID $_rc_p"
    run kill -HUP "$_rc_p"
  done
  return 0
}

# ================================ main ======================================
log "=== AS Java certificate renewal: SID=$SID instance=$INSTANCE_NAME host=$HOST_FQDN ==="
[ "$DRYRUN" = "1" ] && log ">>> DRYRUN active - nothing is changed. Real run: DRYRUN=0 <<<"

# load the telnet password (only needed for an actual view LOAD; java_telnet
# reports an empty password itself). Strip CR so a CRLF/Windows-edited .pw file
# does not send a stray carriage return and fail authentication.
if [ -f "$JAVA_TELNET_PW_FILE" ]; then
  JAVA_TELNET_PW=$(tr -d '\r' < "$JAVA_TELNET_PW_FILE" 2>/dev/null) || JAVA_TELNET_PW=""
fi

# Determine whether the instance is running. When it is down we still stage the
# server certificate into the CRED PSE (served on next start) but skip the ICM
# reload and all Key Storage view / telnet operations (which need a running
# instance). Override with INSTANCE_UP=1|0 in the environment.
if [ -z "${INSTANCE_UP:-}" ]; then
  if instance_running; then INSTANCE_UP=1; else INSTANCE_UP=0; fi
fi
if [ "$INSTANCE_UP" = "0" ]; then
  DEFERRED=1
  log "Instance ${SID}/${INSTANCE_NAME} appears to be DOWN - staging the PSE only;"
  log "ICM reload and Key Storage view operations are deferred to the next run while up."
else
  DEFERRED=0
fi

STEP="find server leaf"
LEAF=$(newest_leaf)
[ -n "$LEAF" ] || die "no server certificate (directory without 'clnt') in $ACME_HOME"
log "Server leaf: $LEAF"

# determine the root CA for the chain
STEP="determine root CA"
ROOT=""; LEAF_DIR=$(dirname "$LEAF")
if [ -n "$ROOT_CA_FILE" ]; then
  [ -f "$ROOT_CA_FILE" ] || die "ROOT_CA_FILE missing: $ROOT_CA_FILE"; ROOT="$ROOT_CA_FILE"
elif [ -f "$LEAF_DIR/root_ca.cer" ]; then
  ROOT="$LEAF_DIR/root_ca.cer"
elif [ -n "$ROOT_CA_SUBJECT_MATCH" ]; then
  for f in /var/lib/ca-certificates/pem/*.pem /etc/ssl/certs/*.pem /etc/pki/tls/certs/*.pem \
           /var/ssl/certs/*.pem /var/ssl/certs/*.crt /opt/freeware/etc/ssl/certs/*.pem; do
    [ -f "$f" ] || continue
    case "$("$OPENSSL" x509 -in "$f" -noout -subject 2>/dev/null)" in
      *"$ROOT_CA_SUBJECT_MATCH"*) ROOT="$f"; break ;;
    esac
  done
fi
if [ -z "$ROOT" ]; then
  log "WARN: no root CA found (root_ca.cer next to leaf / ROOT_CA_FILE / ROOT_CA_SUBJECT_MATCH)."
  log "      Building the p12 from leaf + intermediate only (ca.cer)."
fi
[ -n "$ROOT" ] && log "Root CA: $ROOT"

# ---- per-target idempotency ------------------------------------------------
# The server leaf changes every few months (acme/ARI); a long-lived client p12
# only every few years. Track each target separately so the client view is NOT
# re-loaded on every server renewal (avoids needless LOADs/backups).
fp_of() { "$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//'; }
state_read() {  # $1=key -> value on stdout
  [ -f "$STATE_FILE" ] || return 0
  awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,""); print; exit}' "$STATE_FILE"
}
state_write() {  # $1=key $2=value (replaces/appends line-wise)
  mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null || true
  _sw_new="$STATE_FILE.new.$$"
  { [ -f "$STATE_FILE" ] && grep -v "^$1=" "$STATE_FILE" 2>/dev/null
    printf '%s=%s\n' "$1" "$2"; } > "$_sw_new" 2>/dev/null \
    && mv "$_sw_new" "$STATE_FILE" 2>/dev/null || rm -f "$_sw_new" 2>/dev/null
}

SRV_NOW=$(fp_of "$LEAF")
CLI_NOW=""; [ -f "$CLIENT_P12" ] && CLI_NOW=$(sha256_of_file "$CLIENT_P12")
SERVER_CHANGED=0; CLIENT_CHANGED=0
[ "$SRV_NOW" != "$(state_read srv)" ] && SERVER_CHANGED=1
[ -n "$CLI_NOW" ] && [ "$CLI_NOW" != "$(state_read cli)" ] && CLIENT_CHANGED=1
if [ "$FORCE" = "1" ] || [ "$DRYRUN" = "1" ]; then SERVER_CHANGED=1; CLIENT_CHANGED=1; fi

if [ "$SERVER_CHANGED" != "1" ] && [ "$CLIENT_CHANGED" != "1" ]; then
  log "No certificate change since the last run - nothing to do. (FORCE=1 overrides)"
  exit 0
fi

make_priv_tmp
TMP_P12="$PRIV_TMP/java.p12"

# build the server p12 only if a server-side target runs (and the server changed)
NEED_SRV_P12=0
if [ "$SERVER_CHANGED" = "1" ]; then
  { [ "$DO_SERVER" = "1" ] || [ "$SYNC_SERVER_VIEW" = "1" ] || [ "$DO_SERVICE_SSL" = "1" ]; } \
    && NEED_SRV_P12=1
fi
if [ "$NEED_SRV_P12" = "1" ]; then
  STEP="algorithm guard"
  algo_guard "$LEAF"
  STEP="build server p12"
  build_p12 "$LEAF" "$TMP_P12" "$ROOT" || die "could not build the server p12"
fi

# --- target 1: server (ICM CRED PSE) ----------------------------------------
if [ "$DO_SERVER" = "1" ] && [ "$SERVER_CHANGED" = "1" ]; then
  STEP="server certificate (ICM CRED PSE)"
  _srv_ok=0; _sync_ok=1
  if renew_icm_server "$TMP_P12"; then _srv_ok=1; else echo "WARN: server cert (ICM) not fully renewed"; fi
  if [ "$SYNC_SERVER_VIEW" = "1" ]; then
    if [ "$DRYRUN" != "1" ] && [ "$INSTANCE_UP" = "0" ]; then
      log "Instance down - NWA view sync deferred (needs a running instance)."
      _sync_ok=0
    elif [ "$DRYRUN" != "1" ] && { ! have telnet || [ -z "$JAVA_TELNET_PW" ]; }; then
      log "SYNC_SERVER_VIEW=1 but telnet/password not configured - NWA view sync skipped."
      log "      (The server certificate is still deployed via the CRED PSE.)"
      # intentional server-only setup: do not force a retry
    else
      STEP="sync server view (telnet LOAD)"
      if [ -z "$SERVER_VIEW" ]; then
        SERVER_VIEW=$(resolve_server_view 2>/dev/null) || SERVER_VIEW=""
        [ -n "$SERVER_VIEW" ] && log "Auto-detected server view: $SERVER_VIEW"
      fi
      if [ -z "$SERVER_VIEW" ]; then
        log "SYNC_SERVER_VIEW=1 but the server view could not be resolved - set SERVER_VIEW; sync skipped."
        _sync_ok=0
      else
        # candidate entry aliases, preference order: the certificate's own FQDN
        # (most reliable), then HOST_FQDN, then the short host name, then the SAP
        # standard 'ssl-credentials'. Deduplicated. This reuses whatever existing
        # host-named key entry the view already has instead of adding a new one.
        _srv_dom=$(basename "$LEAF" .cer 2>/dev/null)
        _srv_cands=""
        for _c in "$_srv_dom" "$HOST_FQDN" "${_srv_dom%%.*}" "${HOST_FQDN%%.*}" ssl-credentials; do
          [ -n "$_c" ] || continue
          case " $_srv_cands " in *" $_c "*) ;; *) _srv_cands="$_srv_cands $_c" ;; esac
        done
        if load_view "$SERVER_VIEW" "${SERVER_ALIAS:-$_srv_cands}" "$TMP_P12" "$P12PW"; then
          :
        else
          echo "WARN: server view '$SERVER_VIEW' not synced"
          _sync_ok=0
        fi
      fi
    fi
  fi
  # advance the state only when the cert deployed, the instance was up, and a
  # requested view sync did not fail - so a failed/deferred sync retries next run
  if [ "$_srv_ok" = "1" ] && [ "$_sync_ok" = "1" ] && [ "$INSTANCE_UP" = "1" ] && [ "$DRYRUN" != "1" ]; then
    state_write srv "$SRV_NOW"
  fi
elif [ "$DO_SERVER" = "1" ]; then
  log "Server: unchanged since the last run - skipped."
fi

# --- target 2: client Key Storage view (long-lived clientAuth p12) ----------
if [ "$DO_CLIENT" = "1" ]; then
  if [ "$CLIENT_CHANGED" != "1" ]; then
    log "Client: unchanged since the last run - skipped."
  elif [ "$DRYRUN" != "1" ] && [ "$INSTANCE_UP" = "0" ]; then
    log "Client: instance down - Key Storage view LOAD deferred (needs a running instance)."
  elif [ -z "$CLIENT_VIEW" ] || [ -z "$CLIENT_ALIAS" ]; then
    echo "WARN: DO_CLIENT=1 but CLIENT_VIEW/CLIENT_ALIAS not configured - client skipped."
  elif [ ! -f "$CLIENT_P12" ]; then
    echo "WARN: no client p12 ($CLIENT_P12) - client view '$CLIENT_VIEW' NOT touched."
    echo "      Provide a long-lived clientAuth p12 (a serverAuth-only certificate cannot be a client identity)."
  else
    STEP="client certificate (view '$CLIENT_VIEW', alias '$CLIENT_ALIAS')"
    _cli_src="$CLIENT_P12"
    _cli_pw=""
    [ -f "$CLIENT_P12PW_FILE" ] && _cli_pw=$(cat "$CLIENT_P12PW_FILE" 2>/dev/null || echo "")
    # If the delivered p12 already contains the chain it is loaded directly.
    # If not, repack it with CLIENT_CHAIN (password via 'file:' -> not in 'ps';
    # LOAD then uses the transient P12PW).
    if [ -n "$CLIENT_CHAIN" ] && [ -f "$CLIENT_CHAIN" ]; then
      if "$OPENSSL" pkcs12 -in "$CLIENT_P12" -passin file:"$CLIENT_P12PW_FILE" -nocerts -nodes -out "$PRIV_TMP/ck.key" 2>/dev/null \
         && "$OPENSSL" pkcs12 -in "$CLIENT_P12" -passin file:"$CLIENT_P12PW_FILE" -clcerts -nokeys -out "$PRIV_TMP/cc.crt" 2>/dev/null \
         && "$OPENSSL" pkcs12 -export -inkey "$PRIV_TMP/ck.key" -in "$PRIV_TMP/cc.crt" -certfile "$CLIENT_CHAIN" \
              -name "$CLIENT_ALIAS" -passout pass:"$P12PW" -out "$PRIV_TMP/client_full.p12" 2>/dev/null; then
        _cli_src="$PRIV_TMP/client_full.p12"; _cli_pw="$P12PW"
        secure_rm "$PRIV_TMP/ck.key" "$PRIV_TMP/cc.crt"
      else
        echo "WARN: repack with CLIENT_CHAIN failed - using the delivered p12 directly"
      fi
    fi
    if load_view "$CLIENT_VIEW" "$CLIENT_ALIAS" "$_cli_src" "$_cli_pw"; then
      [ "$DRYRUN" = "1" ] || state_write cli "$CLI_NOW"
    else
      echo "WARN: client view '$CLIENT_VIEW' not renewed"
    fi
    [ "$_cli_src" != "$CLIENT_P12" ] && secure_rm "$_cli_src"
  fi
fi

# --- target 3: service_ssl (legacy; only if actually used) ------------------
if [ "$DO_SERVICE_SSL" = "1" ] && [ "$SERVER_CHANGED" = "1" ]; then
  if [ "$DRYRUN" != "1" ] && [ "$INSTANCE_UP" = "0" ]; then
    log "service_ssl: instance down - view LOAD deferred (needs a running instance)."
  else
    STEP="service_ssl (view '$SERVICE_SSL_VIEW')"
    load_view "$SERVICE_SSL_VIEW" "$SERVICE_SSL_ALIAS" "$TMP_P12" "$P12PW" \
      || echo "WARN: view '$SERVICE_SSL_VIEW' not renewed"
  fi
fi

# (the idempotency state is advanced per target via state_write above)

# --- prune old ICM PSE + keystore backups (keep the last 5 of each) ---------
( ls -t "$INST_SEC"/SAPSSLS.pse.*.bak 2>/dev/null | tail -n +6 | while IFS= read -r _bak; do
    [ -n "$_bak" ] && run rm -f "$_bak"
  done ) 2>/dev/null || true
( ls -t "$STAGE_DIR"/keystore_backup_*.bak 2>/dev/null | tail -n +6 | while IFS= read -r _bak; do
    [ -n "$_bak" ] && run rm -f "$_bak"
  done ) 2>/dev/null || true

log "Done."
if [ "$DRYRUN" = "1" ]; then
  log ">>> This was a DRYRUN. For a real run: DRYRUN=0 ./$(basename "$0") <<<"
fi
exit 0
