# AyDee

AyDee - Active Directory recon.

Point it at a target and it runs one automatic pipeline:

`Port Scan -> Service Discovery -> Unauth Recon -> Auth Recon (if creds) -> Credential Attacks -> BloodHound (if possible)`

## Build

```bash
cargo build --release
```

Binary:

```bash
./target/release/aydee
```

## Usage

```bash
aydee [OPTIONS] <TARGET>
```

Examples:

```bash
# default scan + auto-dispatch
aydee 10.10.10.100

# custom ports
aydee 10.10.10.100 -p 389,636,8080

# all ports
aydee 10.10.10.100 -p- --timeout 3

# password auth
aydee 10.10.10.100 -d corp.local -u alice -P 'Password123!'

# NTLM auth
aydee 10.10.10.100 -d corp.local -u alice -H aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff

# Kerberos via ccache
aydee 10.10.10.100 --ccache ./alice.ccache -k -u alice

# BloodHound all collection
aydee 10.10.10.100 --collection All -u alice -k --ccache ./alice.ccache
```

## Options

### Scan

- `-p, --ports <PORTS>` custom ports (`389,636`, ranges like `80-100`, or `-` for all)
- `-t, --timeout <TIMEOUT>` connection timeout seconds (default `2`)
- `--no-fix-clock-skew` disable startup clock skew fix helper
- `-d, --domain <DOMAIN>` domain hint (otherwise auto-discovered)
- `-w, --wordlist <WORDLIST>` custom Kerberos user enum wordlist

### Authentication

- `-u, --username <USERNAME>` username
- `-P, --password <PASSWORD>` password
- `-H, --ntlm <NTLM>` NTHASH or LMHASH:NTHASH
- `-k, --kerberos` enable Kerberos auth mode for external collectors
- `--ccache <CCACHE>` Kerberos ticket cache path (sets `KRB5CCNAME`)

### Collection / Output

- `--collection <COLLECTION>` BloodHound scope (default `All`)
- `--report-json <REPORT_JSON>` JSON report filename (default `aydee_report.json`)

## What It Tries

Based on open ports and available creds/data, aydee attempts:

- DNS discovery and domain inference
- LDAP/GC unauth recon and user/domain harvesting
- SMB unauth checks (NTLM info, signing, SMBv1, null session) and authenticated share recon
- RPC endpoint surface checks
- Kerberos user enumeration
- Credential attack paths (including AS-REP / Kerberoast tooling integrations when possible)
- BloodHound collection (`--collection All --zip`) when credentials/domain are available

## Output Layout

Every run creates a timestamped directory:

`results/<target>_<unix_timestamp>/`

Artifacts (reports, hashes, tickets, tool outputs) are written under that run directory.

## Notes

- Domain is auto-discovered from target identity, DNS, LDAP, and SMB where possible.
- If Kerberos-related actions are in scope, aydee attempts startup clock sync unless disabled.
- External tooling availability (e.g., impacket/bloodhound-python/certipy/nxc) affects which sub-steps can execute.

## Legal

Use only on systems you own or have explicit permission to test.
