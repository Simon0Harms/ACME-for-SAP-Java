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
INST="${INST:-00}"                         # instance number (two digits)
INSTANCE_NAME="${INSTANCE_NAME:-J00}"      # instance directory name, e.g. J00

# SID: use the configured/env value; otherwise auto-detect. Detection prefers
# the unique system that owns this INSTANCE_NAME directory, then falls back to
# the only system that has a profile directory. On a host with more than one SAP
# system (e.g. a Diagnostics Agent alongside), set SID explicitly.
_detect_sid() {
  set --
  for _d in "$USR_SAP"/*/; do
    _s=$(basename "$_d")
    case "$_s" in [A-Z][A-Z0-9][A-Z0-9]) ;; *) continue ;; esac
    [ -d "$USR_SAP/$_s/$INSTANCE_NAME" ] && set -- "$@" "$_s"
  done
  if [ "$#" -eq 1 ]; then printf '%s' "$1"; return 0; fi
  set --
  for _d in "$USR_SAP"/*/; do
    _s=$(basename "$_d")
    case "$_s" in [A-Z][A-Z0-9][A-Z0-9]) ;; *) continue ;; esac
    [ -d "$USR_SAP/$_s/SYS/profile" ] && set -- "$@" "$_s"
  done
  [ "$#" -eq 1 ] && { printf '%s' "$1"; return 0; }
  return 1
}
SID="${SID:-}"
[ -n "$SID" ] || SID=$(_detect_sid 2>/dev/null) || SID=""

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
ICM_CRED_PSE="${ICM_CRED_PSE:-$INST_SEC/SAPSSLS.pse}"   # from icm/ssl_config_* CRED=

# Staging directory for the telnet LOAD - MUST be located under /usr/sap/<SID>/
STAGE_DIR="${STAGE_DIR:-$USR_SAP/$SID/SYS/global/security/data}"

# External tools (on AIX possibly under /opt/freeware/bin/...)
OPENSSL="${OPENSSL:-openssl}"
PERL="${PERL:-perl}"

# Ports (default formulas: HTTPS = 5<NR>01, TELNET = 5<NR>08)
HTTPS_PORT="${HTTPS_PORT:-$(printf '5%s01' "$INST")}"
TELNET_HOST="${TELNET_HOST:-127.0.0.1}"
TELNET_PORT="${TELNET_PORT:-$(printf '5%s08' "$INST")}"

# Telnet admin access (UME admin). Password from a protected file (chmod 600).
JAVA_TELNET_USER="${JAVA_TELNET_USER:-Administrator}"
JAVA_TELNET_PW_FILE="${JAVA_TELNET_PW_FILE:-/root/sap_certs/${SID}_telnet.pw}"
KEYSTORE_GROUP="${KEYSTORE_GROUP:-keystore}"   # telnet command group name
                                               # (verify with bare 'man' in the console)
# Telnet timing (POSIX piping is timing sensitive; raise these if LOADs fail)
TELNET_WAIT="${TELNET_WAIT:-2}"                # after connect / login
TELNET_STEP_WAIT="${TELNET_STEP_WAIT:-2}"      # between commands

# Key Storage view / entry names. The ICM_SSL views contain the instance id
# (e.g. ICM_SSL_39631_50001). SERVER_VIEW is auto-detected when left empty (from
# j2ee/instance_id + the HTTPS port, validated against LISTVIEWSNAMES). The
# client view is site specific; set it if DO_CLIENT=1.
SERVER_VIEW="${SERVER_VIEW:-}"                  # empty -> auto-detect ICM_SSL_<instid>_<port>
SERVER_ALIAS="${SERVER_ALIAS:-ssl-credentials}" # standard entry name for ICM_SSL views
CLIENT_VIEW="${CLIENT_VIEW:-}"                   # e.g. CLIENT_ICM_SSL_<instid>
CLIENT_ALIAS="${CLIENT_ALIAS:-}"                # EXACT existing entry name (from NWA)
SERVICE_SSL_VIEW="${SERVICE_SSL_VIEW:-service_ssl}"
SERVICE_SSL_ALIAS="${SERVICE_SSL_ALIAS:-ssl-credentials}"

# Optional: if LOAD does not overwrite an existing alias on your console, set the
# console's delete command here; it is then run as "<cmd> <view> <alias>" before
# LOAD. Empty = LOAD only (relies on overwrite). Verify the exact command/syntax
# with bare 'man' in the telnet console before enabling.
KEYSTORE_DELETE_CMD="${KEYSTORE_DELETE_CMD:-}"

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
  echo "ERROR: could not determine the SAP SID automatically" >&2
  echo "       (none or several systems found under $USR_SAP)." >&2
  echo "       Set SID in sap_java_cert_renew.conf (next to the script) or via SID=..." >&2
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
    report_checkmk 2 "-" "AS Java certificate renewal FAILED: $_cu_msg"
    send_mail "CRIT: AS Java certificate $SID" "The renewal failed.

$_cu_msg"
    return
  fi
  _cu_days=$(days_left "${LEAF:-}")
  _cu_exp=$("$OPENSSL" x509 -in "${LEAF:-}" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  _cu_state=0
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

# ---- algorithm-change guard ------------------------------------------------
algo_guard() {  # $1 = new leaf
  _ag_new=$(key_algo_of_cert "$1")
  _ag_cur=$(served_key_algo)
  log "Algorithm: currently served='${_ag_cur:-unknown}', new='$_ag_new'"
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
# stdin with sleeps. If LOADs fail intermittently, raise TELNET_WAIT. Passwords
# go through stdin, not argv -> not visible in 'ps'.
java_telnet() {  # $1=file with commands (one per line), $2=transcript output
  _jt_cmds="$1"; _jt_out="$2"
  if ! have telnet; then echo "java_telnet: 'telnet' not found" >&2; return 1; fi
  if [ -z "$JAVA_TELNET_PW" ]; then
    echo "java_telnet: telnet password is empty ($JAVA_TELNET_PW_FILE, chmod 600)" >&2; return 1
  fi
  (
    sleep "$TELNET_WAIT"
    printf '%s\r\n' "$JAVA_TELNET_USER"; sleep "$TELNET_WAIT"
    printf '%s\r\n' "$JAVA_TELNET_PW";   sleep "$TELNET_WAIT"
    printf 'add %s\r\n' "$KEYSTORE_GROUP"; sleep "$TELNET_STEP_WAIT"
    while IFS= read -r _jt_line; do
      printf '%s\r\n' "$_jt_line"; sleep "$TELNET_STEP_WAIT"
    done < "$_jt_cmds"
    printf 'exit\r\n'; sleep "$TELNET_WAIT"
  ) | telnet "$TELNET_HOST" "$TELNET_PORT" > "$_jt_out" 2>&1 || true
  chmod 600 "$_jt_out" 2>/dev/null || true
  return 0
}

# ---- stage a p12 under /usr/sap/<SID>/ (LOAD restriction) ------------------
stage_p12() {  # $1=source.p12 $2=target-name -> full path on stdout
  mkdir -p "$STAGE_DIR" 2>/dev/null || { echo "" ; return 1; }
  _sp_dst="$STAGE_DIR/$2"
  cp -p "$1" "$_sp_dst" 2>/dev/null || { echo ""; return 1; }
  chmod 600 "$_sp_dst" 2>/dev/null || true
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
keystore_views() {  # -> one view name per line (best effort)
  [ "$DRYRUN" = "1" ] && return 0
  have telnet || return 0
  [ -n "$JAVA_TELNET_PW" ] || return 0
  _kv_cmd="$PRIV_TMP/tn_listviews.cmd"; _kv_out="$PRIV_TMP/tn_listviews.out"
  printf 'LISTVIEWSNAMES\n' > "$_kv_cmd"
  java_telnet "$_kv_cmd" "$_kv_out" || { secure_rm "$_kv_cmd" "$_kv_out"; return 0; }
  # keep only bare token lines (view names are [A-Za-z0-9_]); drops banner/prompts
  sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "$_kv_out" 2>/dev/null | grep -E '^[A-Za-z0-9_]+$'
  secure_rm "$_kv_cmd" "$_kv_out"
}

# ---- resolve the server view: ICM_SSL_<instid>_<port>, else ICM_SSL_<instid> -
resolve_server_view() {  # -> view name (best effort) or empty
  _rsv_id=$(_instid_from_profile 2>/dev/null)
  [ -n "$_rsv_id" ] || return 0
  _rsv_primary="ICM_SSL_${_rsv_id}_${HTTPS_PORT}"
  _rsv_fallback="ICM_SSL_${_rsv_id}"
  # no live validation possible -> return the best-guess primary
  if [ "$DRYRUN" = "1" ] || ! have telnet || [ -z "$JAVA_TELNET_PW" ]; then
    printf '%s' "$_rsv_primary"; return 0
  fi
  _rsv_views=$(keystore_views)
  if printf '%s\n' "$_rsv_views" | grep -Fxq "$_rsv_primary"; then
    printf '%s' "$_rsv_primary"
  elif printf '%s\n' "$_rsv_views" | grep -Fxq "$_rsv_fallback"; then
    printf '%s' "$_rsv_fallback"
  else
    printf '%s' "$_rsv_primary"
  fi
}

# ---- renew one Key Storage view via telnet ---------------------------------
# BACKUP the whole keystore -> LOAD -> LIST (verification).
load_view() {  # $1=view $2=alias $3=source.p12 $4=password(optional) -> rc
  _lv_view="$1"; _lv_alias="$2"; _lv_src="$3"; _lv_pw="${4:-$P12PW}"
  if [ -z "$_lv_view" ] || [ -z "$_lv_alias" ]; then
    echo "load_view: view or alias not configured - skipped"; return 1
  fi
  _lv_ts=$(date +%Y%m%d%H%M%S)
  _lv_bak="$STAGE_DIR/keystore_backup_${_lv_ts}.bak"
  _lv_stage_name="acme_java_${_lv_view}_${_lv_ts}.p12"

  # DRYRUN: preview WITH a masked password (no cleartext PW in log / acme output)
  if [ "$DRYRUN" = "1" ]; then
    log "View '$_lv_view': (DRYRUN) BACKUP -> LOAD (alias '$_lv_alias') -> LIST"
    printf '  [DRYRUN] telnet %s %s -- login as %s, add %s, then:\n' \
      "$TELNET_HOST" "$TELNET_PORT" "$JAVA_TELNET_USER" "$KEYSTORE_GROUP"
    printf '    | BACKUP %s\n' "$_lv_bak"
    [ -n "$KEYSTORE_DELETE_CMD" ] && printf '    | %s %s %s\n' "$KEYSTORE_DELETE_CMD" "$_lv_view" "$_lv_alias"
    printf '    | LOAD %s %s -PKCS12 %s ********\n' "$_lv_view" "$_lv_alias" "$STAGE_DIR/$_lv_stage_name"
    printf '    | LIST %s\n' "$_lv_view"
    return 0
  fi

  _lv_stage=$(stage_p12 "$_lv_src" "$_lv_stage_name") || _lv_stage=""
  [ -n "$_lv_stage" ] || { echo "load_view: staging failed ($STAGE_DIR)"; return 1; }

  _lv_cmdf="$PRIV_TMP/tn_${_lv_view}.cmd"
  _lv_outf="$PRIV_TMP/tn_${_lv_view}.out"
  {
    printf 'BACKUP %s\n' "$_lv_bak"
    [ -n "$KEYSTORE_DELETE_CMD" ] && printf '%s %s %s\n' "$KEYSTORE_DELETE_CMD" "$_lv_view" "$_lv_alias"
    printf 'LOAD %s %s -PKCS12 %s %s\n' "$_lv_view" "$_lv_alias" "$_lv_stage" "$_lv_pw"
    printf 'LIST %s\n' "$_lv_view"
  } > "$_lv_cmdf"
  chmod 600 "$_lv_cmdf" 2>/dev/null || true

  log "View '$_lv_view': BACKUP -> LOAD (alias '$_lv_alias') -> LIST"
  java_telnet "$_lv_cmdf" "$_lv_outf" || { secure_rm "$_lv_cmdf" "$_lv_stage"; return 1; }

  _lv_rc=0
  # verification: alias present in LIST output, no obvious errors
  if grep -qi -e 'error' -e 'exception' -e 'not found' -e 'no such' "$_lv_outf" 2>/dev/null; then
    echo "WARN: telnet output contains error hints for view '$_lv_view' - please check:"
    grep -i -e error -e exception -e 'not found' -e 'no such' "$_lv_outf" | sed 's/^/    > /' | head -n 5
    _lv_rc=1
  fi
  if ! grep -q "$_lv_alias" "$_lv_outf" 2>/dev/null; then
    echo "WARN: alias '$_lv_alias' not found in LIST of '$_lv_view' after LOAD."
    _lv_rc=1
  fi
  # the command file holds the cleartext password -> wipe it
  secure_rm "$_lv_cmdf" "$_lv_stage"
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

# ---- reload the ICM (SIGHUP to the instance's icman; fallback: restart) -----
reload_icm() {
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
# reports an empty password itself)
if [ -f "$JAVA_TELNET_PW_FILE" ]; then
  JAVA_TELNET_PW=$(cat "$JAVA_TELNET_PW_FILE" 2>/dev/null) || JAVA_TELNET_PW=""
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
  if renew_icm_server "$TMP_P12"; then
    [ "$DRYRUN" = "1" ] || state_write srv "$SRV_NOW"
  else
    echo "WARN: server cert (ICM) not fully renewed"
  fi
  if [ "$SYNC_SERVER_VIEW" = "1" ]; then
    if [ "$DRYRUN" != "1" ] && { ! have telnet || [ -z "$JAVA_TELNET_PW" ]; }; then
      log "SYNC_SERVER_VIEW=1 but telnet/password not configured - NWA view sync skipped."
      log "      (The server certificate is still deployed via the CRED PSE.)"
    else
      STEP="sync server view (telnet LOAD)"
      if [ -z "$SERVER_VIEW" ]; then
        SERVER_VIEW=$(resolve_server_view)
        [ -n "$SERVER_VIEW" ] && log "Auto-detected server view: $SERVER_VIEW"
      fi
      if [ -z "$SERVER_VIEW" ]; then
        log "SYNC_SERVER_VIEW=1 but the server view could not be resolved - set SERVER_VIEW; sync skipped."
      else
        load_view "$SERVER_VIEW" "$SERVER_ALIAS" "$TMP_P12" "$P12PW" \
          || echo "WARN: server view '$SERVER_VIEW' not synced"
      fi
    fi
  fi
elif [ "$DO_SERVER" = "1" ]; then
  log "Server: unchanged since the last run - skipped."
fi

# --- target 2: client Key Storage view (long-lived clientAuth p12) ----------
if [ "$DO_CLIENT" = "1" ]; then
  if [ "$CLIENT_CHANGED" != "1" ]; then
    log "Client: unchanged since the last run - skipped."
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
  STEP="service_ssl (view '$SERVICE_SSL_VIEW')"
  load_view "$SERVICE_SSL_VIEW" "$SERVICE_SSL_ALIAS" "$TMP_P12" "$P12PW" \
    || echo "WARN: view '$SERVICE_SSL_VIEW' not renewed"
fi

# (the idempotency state is advanced per target via state_write above)

# --- prune old ICM PSE backups (keep the last 5) ----------------------------
( ls -t "$INST_SEC"/SAPSSLS.pse.*.bak 2>/dev/null | tail -n +6 | while IFS= read -r _bak; do
    [ -n "$_bak" ] && run rm -f "$_bak"
  done ) 2>/dev/null || true

log "Done."
if [ "$DRYRUN" = "1" ]; then
  log ">>> This was a DRYRUN. For a real run: DRYRUN=0 ./$(basename "$0") <<<"
fi
exit 0
