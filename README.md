<p align="center">
  <img src="https://img.shields.io/badge/version-2.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/lang-Rust-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

<h1 align="center">AyDee</h1>

<p align="center">
  <b>Active Directory reconnaissance and attack-surface mapping from a single CLI.</b><br>
  One command. One results directory. Full first-pass AD triage.
</p>

---

AyDee replaces the "open 12 terminals and glue scripts together" phase of an AD engagement. Point it at a domain controller, hand it credentials (or don't), and it walks through discovery, enumeration, roasting, BloodHound collection, and attack-surface analysis — writing everything into one workspace.

## Pipeline

```
 [1] Port Scan ─► [2] DNS ─► [3] LDAP ─► [4] SMB / WinRM / RPC
         │                        │
         ▼                        ▼
 [5] Kerberos  ─► [6] Attacks ─► [7] BloodHound ─► [8] Report
         │              │
    Roasting       Coercion
    AS-REP         SMB Signing
    Spray          Relay Map
```

Each stage feeds the next. Missing tools or closed ports don't abort the run — AyDee skips the affected path and keeps going.

## Features

### Reconnaissance & Enumeration

| Area | What AyDee Does |
|------|-----------------|
| **Port Scan** | Fast async TCP scan with service fingerprinting (Kerberos, LDAP, SMB, MSSQL, RDP, WinRM, ...) |
| **DNS** | SRV enumeration, zone transfer attempt, dynamic update check, domain auto-discovery |
| **LDAP** | Anonymous bind check, RootDSE fingerprint, authenticated directory enumeration |
| **SMB** | Null session check, share enumeration, SYSVOL walk, GPP credential extraction |
| **WinRM** | Credential validation |
| **RPC** | RID cycling, null session enumeration |

### Security Analysis

| Check | Detail |
|-------|--------|
| **Kerberoasting** | SPN-bearing accounts with crackable encryption |
| **AS-REP Roasting** | Accounts without pre-authentication |
| **Delegation** | Unconstrained, constrained (with protocol transition differentiation), and RBCD |
| **ADCS** | ESC1 through ESC6 detection via certificate template and CA analysis |
| **Password Policy** | Domain lockout thresholds, complexity, max age — fed into spray safety |
| **LAPS** | v1 (`ms-Mcs-AdmPwd`) and v2 (`msLAPS-Password` / `msLAPS-EncryptedPassword`) deployment checks |
| **gMSA** | Managed service account discovery with `msDS-ManagedPasswordId` readability |
| **AdminSDHolder** | Non-default accounts with `adminCount=1` (potential orphans) |
| **SID History** | Accounts with `sIDHistory` set — privilege escalation indicator |
| **Privileged Groups** | Recursive membership expansion across Domain Admins, Enterprise Admins, Schema Admins, DnsAdmins, and operator groups |
| **Inactive Accounts** | Enabled accounts with no logon in 90+ days |
| **Deleted Objects** | AD Recycle Bin enumeration for recoverable accounts |
| **Service Accounts** | Heuristic name-matching with password-never-expires and admin-privilege flagging |
| **Pre-Windows 2000** | Checks if Authenticated Users / Everyone are in the Pre-Windows 2000 group |
| **MAQ** | Machine Account Quota for RBCD abuse |
| **SMB Signing** | Negotiate-level check — signing enabled vs. required |
| **Coercion** | PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce pipe probing via real SMB2 |
| **DNS Dynamic Update** | `nsupdate` probe for unauthenticated zone modification |
| **Password Spray** | Policy-aware spraying with lockout safety calculation |
| **BloodHound** | Automated collection via `bloodhound-python` / `bloodhound-ce-python` with auth cascade |

### Attack Path Correlation

AyDee cross-references findings after all modules complete to surface composite attack chains:

```
Coercion + ADCS ESC8           → relay to Web Enrollment → domain admin cert
Coercion + no SMB signing      → relay to SMB for code execution
MAQ > 0 + no SMB signing       → create machine account + RBCD relay
MAQ + coercion + ESC8          → full relay chain
WebDAV + coercion              → cross-protocol relay (HTTP→LDAP/SMB)
ESC1 template                  → enroll cert as any user → PKINIT
```

### Reporting

Every run produces a workspace under `results/<target>_<timestamp>/`:

| File | Purpose |
|------|---------|
| `aydee_report.json` | Structured findings for scripting and ingestion |
| `aydee_report.md` | Markdown report with severity-grouped findings, MITRE references, and tables |
| `aydee_report.html` | Standalone HTML report with risk scoring |
| `aydee_summary.txt` | Quick plaintext overview |
| `workspace_manifest.json` | Index of all generated artifacts |
| `bloodhound_output/` | BloodHound collection ZIPs |
| `*_hashes_*.txt` | Kerberoast / AS-REP roast hashes |
| `*.ccache` | Tickets from successful pre2k / machine-account hits |

---

## Installation

### Prebuilt Binaries

Grab the latest from [GitHub Releases](../../releases):

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `aydee-v<version>-linux-x86_64` |
| Windows x86_64 | `aydee-v<version>-windows-x86_64.exe` |

### Build From Source

```bash
# Requires: Rust toolchain
cargo build --release
./target/release/aydee --help
```

### Runtime Dependencies

AyDee gracefully skips modules when their external tools are missing.

| Category | Tools |
|----------|-------|
| **Core** | `smbclient`, `nxc` / `netexec` / `crackmapexec`, `dig`, `ntpdate` / `rdate` |
| **BloodHound** | `bloodhound-python` or `bloodhound-ce-python` |
| **Impacket** | `impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-getTGT` (or `.py` variants) |
| **DNS** | `nsupdate` (for dynamic update check) |

> **Note:** The Windows binary is published via CI, but the full feature set works best on Linux where the external operator tooling lives.

---

## Quick Start

### Anonymous Fingerprinting

```bash
aydee --target 10.10.10.100
```

### Password Auth

```bash
aydee --target 10.10.10.100 -u alice -p 'Password123!'
```

### NTLM Hash

```bash
aydee --target 10.10.10.100 -d corp.local -u alice \
  -H aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff
```

### Kerberos

```bash
aydee --target 10.10.10.100 -d corp.local -u alice -k --ccache ./alice.ccache
```

### Single Module

```bash
aydee --target 10.10.10.100 -d corp.local -u alice -p 'Pass!' --only bloodhound
```

### Focused Checks by Tag

```bash
aydee --target 10.10.10.100 -u alice -p 'Pass!' \
  --only ldap-auth --tags adcs,delegation,sidhistory
```

### Password Spray

```bash
aydee --target 10.10.10.100 -d corp.local \
  --mode manual --only spray \
  --spray-passwords 'Winter2025!,Spring2026!' \
  --userlist ./users.txt
```

### Verbose + Quiet

```bash
aydee --target 10.10.10.100 -u alice -p 'Pass!' -v    # see subprocess output
aydee --target 10.10.10.100 -u alice -p 'Pass!' -q    # findings only, no banner/info
```

---

## Authentication

| Mode | Flags | Notes |
|------|-------|-------|
| **Anonymous** | *(none)* | Authenticated stages are skipped |
| **Password** | `-u` + `-p` | |
| **NTLM** | `-u` + `-H` | Accepts `NTHASH` or `LMHASH:NTHASH` |
| **Kerberos** | `-u` + `-k` | Optional `--ccache`; auto-detects `KRB5CCNAME` |

- `-k` is required to activate Kerberos — a ccache alone doesn't enable it.
- Incomplete credentials skip authenticated modules instead of failing.

## Run Modes

| Mode | Behavior |
|------|----------|
| `auto` | Default. Full non-invasive pipeline. |
| `semi` | Conservative. Skips noisy stages (`kerberos`, `spray`, `credential`, `bloodhound`) unless explicitly selected. |
| `manual` | Only runs modules listed in `--only`. |

## Modules

Use with `--only` (comma-separated):

```
scan  dns  ldap  ldap-auth  smb-auth  rpc  winrm  kerberos  spray  credential  bloodhound  attacks
```

Aliases: `auth-ldap` → `ldap-auth`, `credential-attacks` → `credential`

## Tags

Use with `--tags` to narrow LDAP/SMB subchecks:

```
kerberoast  asreproast  delegation  maq  trusts  adcs  computers  pso  dcsync
laps  gpo  shadow-creds  gmsa  user-desc  policy  deleted  pre2000  inactive
privgroups  adminsdholder  sidhistory  svc-accounts  gpp  sysvol
```

---

## Options Reference

```
TARGET & AUTH
  -t, --target <IP|HOST>     Target (required). Alias: --dc
  -d, --domain <DOMAIN>      Domain name (auto-discovered if omitted)
  -u, --username <USER>      Username
  -p, --password <PASS>      Password
  -H, --ntlm <HASH>          NTLM hash
  -k, --kerberos              Enable Kerberos auth
      --ccache <PATH>         Kerberos ccache file

SCOPE
  -m, --mode <MODE>           auto | semi | manual
      --only <MODULES>        Module allowlist
      --tags <TAGS>           Subcheck filter
      --collection <SCOPE>    BloodHound scope (default: All)

SCANNING
  -P, --ports <SPEC>          Port list, range, or "-" for all
      --timeout <SECS>        TCP connect timeout (default: 2)
      --ldap-port <PORT>      LDAP port override (default: 389)

SPRAY
      --spray-passwords <P>   Comma-separated passwords
      --userlist <PATH>       User list file
      --spray-limit <N>       Max users per round (default: 50)
      --spray-delay <MS>      Delay between attempts (default: 100)

KERBEROS
  -w, --wordlist <PATH>       User enumeration wordlist

OUTPUT
  -o, --output <DIR>          Custom output directory
      --report-json <PATH>    JSON report filename
      --report-text <PATH>    Text summary filename
      --manifest-json <PATH>  Manifest filename

BEHAVIOR
  -v, --verbose               Show subprocess output and debug info
  -q, --quiet                 Suppress info/banner, show findings only
      --no-fix-clock-skew     Skip startup clock sync
      --non-interactive       Suppress all prompts
```

---

## How It Works

**Clock Sync** — Before scanning, AyDee offers to sync your clock with the DC (important for Kerberos). If you're not root, it prompts for sudo.

**Domain Discovery** — If `-d` is omitted, AyDee discovers the domain from DNS PTR records, LDAP RootDSE, or target hostname resolution.

**Target Validation** — After the port scan, AyDee warns if the target doesn't look like a DC (missing Kerberos/LDAP ports).

**Proxychains Detection** — Detects `LD_PRELOAD` / `PROXYCHAINS_CONF_FILE` and warns that UDP-based modules (DNS, NTP) will likely fail.

**Password Policy Awareness** — The domain password policy is extracted via LDAP and passed to the spray module. If your password count would exceed the safe lockout threshold, AyDee warns you before spraying.

**BloodHound Auth Cascade** — Tries password → NTLM → Kerberos authentication. Falls back to `--dns-tcp` on resolution failures. Streams real-time output with `-v`.

**Graceful Degradation** — Missing external tools, closed ports, or failed auth don't kill the run. AyDee logs what it skipped and continues.

---

## Legal

Use AyDee only on networks and systems you own or have explicit written authorization to assess. Unauthorized use is illegal. The authors assume no liability for misuse.
