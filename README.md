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

# semi-auto recon only (skip noisy attack/collection stages)
aydee 10.10.10.100 --mode semi

# manual module selection
aydee 10.10.10.100 --mode manual --only dns,ldap,smb --tags users,policy,signing

# explicit SMB password spray
aydee 10.10.10.100 --mode manual --only spray --spray-password 'Winter2024!' --spray-userlist ./users.txt

# custom ports
aydee 10.10.10.100 -P 389,636,8080

# all ports
aydee 10.10.10.100 -P- --timeout 3

# password auth
aydee 10.10.10.100 -d corp.local -u alice -p 'Password123!'

# NTLM auth
aydee 10.10.10.100 -d corp.local -u alice -H aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff

# Kerberos via ccache
aydee 10.10.10.100 --ccache ./alice.ccache -k -u alice

# BloodHound all collection
aydee 10.10.10.100 --collection All -u alice -k --ccache ./alice.ccache
```

## Options

### Scan

- `-P, --ports <PORTS>` custom ports (`389,636`, ranges like `80-100`, or `-` for all)
- `-t, --timeout <TIMEOUT>` connection timeout seconds (default `2`)
- `--no-fix-clock-skew` disable startup clock skew fix helper
- `-d, --domain <DOMAIN>` domain hint (otherwise auto-discovered)
- `-w, --wordlist <WORDLIST>` custom Kerberos user enum wordlist

### Execution

- `--mode <MODE>` execution mode: `auto`, `semi`, or `manual`
- `--only <MODULES>` comma-separated module allowlist (`dns,ldap,auth-ldap,smb,spray,rpc,attacks,kerberos,credential-attacks,winrm,bloodhound`)
- `--tags <TAGS>` comma-separated check tags forwarded to LDAP/SMB/auth LDAP checks
- `--non-interactive` disable interactive prompts and skip prompt-driven retries
- `--spray-password <PASSWORD>` explicit password candidate for SMB password spraying
- `--spray-userlist <FILE>` optional username file for spraying
- `--spray-max-users <N>` cap spray attempts (default `50`)
- `--spray-delay-ms <MS>` delay between spray attempts (default `250`)

### Authentication

- `-u, --username <USERNAME>` username
- `-p, --password <PASSWORD>` password
- `-H, --ntlm <NTLM>` NTHASH or LMHASH:NTHASH
- `-k, --kerberos` enable Kerberos auth mode for external collectors
- `--ccache <CCACHE>` Kerberos ticket cache path (sets `KRB5CCNAME`)

### Collection / Output

- `--collection <COLLECTION>` BloodHound scope (default `All`)
- `--report-json <REPORT_JSON>` JSON report filename (default `aydee_report.json`)
- `--report-text <REPORT_TEXT>` plaintext operator summary filename (default `aydee_summary.txt`)
- `--manifest-json <MANIFEST_JSON>` workspace manifest filename (default `workspace_manifest.json`)

## What It Tries

Based on open ports and available creds/data, aydee attempts:

- DNS discovery and domain inference
- LDAP/GC unauth recon and user/domain harvesting
- SMB unauth checks (NTLM info, signing, SMBv1, null session) and authenticated share recon
- SYSVOL XML looting and GPP `cpassword` discovery during authenticated SMB recon
- WinRM authenticated credential validation checks (when 5985/5986 are open)
- RPC endpoint surface checks
- Kerberos user enumeration
- Optional SMB password spraying with explicit operator-supplied password candidates
- Credential attack paths (including AS-REP / Kerberoast tooling integrations when possible)
- BloodHound collection (`--collection All --zip`) when credentials/domain are available

## Output Layout

Every run creates a timestamped directory:

`results/<target>_<unix_timestamp>/`

Artifacts (reports, hashes, tickets, tool outputs) are written under that run directory.

Default report artifacts:

- `aydee_report.json` structured run report with module status, open ports, findings, and metadata
- `aydee_summary.txt` plaintext operator summary
- `workspace_manifest.json` artifact index for the run workspace

## Notes

- Domain is auto-discovered from target identity, DNS, LDAP, and SMB where possible.
- If Kerberos-related actions are in scope, aydee attempts startup clock sync unless disabled.
- `--mode semi` skips noisier stages (`spray`, `kerberos`, `credential-attacks`, `bloodhound`) unless explicitly re-enabled with `--only`.
- `--mode manual` requires `--only` and runs only the requested modules.
- Kerberos auth paths are only used when `-k/--kerberos` is explicitly provided. A ccache alone will not auto-enable Kerberos mode.
- When authenticated abuse indicators are detected, aydee can prompt (default `N`) to attempt a temporary fake-SPN write + roast + cleanup flow.
- `--non-interactive` suppresses interactive confirmations and privileged retry prompts.
- Password spraying is opt-in only via `--spray-password`; aydee will not reuse `--password` as a spray candidate automatically.
- BloodHound collection now retries with `--dns-tcp` when DNS resolution via UDP fails/timeouts.
- Successful BloodHound collection now summarizes discovered zip artifacts under `bloodhound_output/`.
- External credential attack helper commands are bounded by internal timeouts to avoid indefinite hangs.
- External tooling availability (e.g., impacket/bloodhound-python/certipy/nxc) affects which sub-steps can execute.

## Legal

Use only on systems you own or have explicit permission to test.
