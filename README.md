# AyDee

AyDee is an Active Directory reconnaissance and attack-surface automation tool for operators who want one CLI to drive the common early AD workflow:

`scan -> fingerprint -> auth validation -> LDAP/SMB/WinRM recon -> roast attacks -> BloodHound -> reports`

It is designed to make practical decisions from what it discovers instead of forcing a long list of separate commands.

## What It Does

- Scans the usual AD ports and labels entry points
- Auto-discovers the domain from target identity, DNS, and LDAP where possible
- Performs LDAP RootDSE fingerprinting and anonymous bind checks
- Runs authenticated LDAP recon for users, SPNs, AS-REP candidates, delegation, trusts, AD CS hints, LAPS, GPOs, and more
- Performs authenticated SMB recon, share listing, SYSVOL enumeration, and GPP password hunting
- Validates WinRM credentials
- Collects BloodHound data with password, NTLM, or Kerberos auth when possible
- Runs credential attack automation:
  Kerberoast via password, NTLM, and Kerberos
  AS-REP roast via password, NTLM, Kerberos, and no-auth against discovered users
  pre2k/default machine-account `getTGT` attempts from discovered machine candidates
- Produces JSON, text, HTML, and workspace-manifest outputs for every run

## Requirements

Rust is required to build the binary.

Some modules depend on external tools. AyDee will skip the relevant path if they are not installed.

- `smbclient`
- `nxc`, `netexec`, or `crackmapexec`
- `bloodhound-python` or `bloodhound-ce-python`
- `GetUserSPNs.py` or `impacket-GetUserSPNs`
- `GetNPUsers.py` or `impacket-GetNPUsers`
- `getTGT.py` or `impacket-getTGT`
- `dig`
- `ntpdate` or `rdate`

## Build

```bash
cargo build --release
```

Binary:

```bash
./target/release/aydee
```

## Quick Start

Password-backed recon:

```bash
./aydee --target 10.10.10.100 -u alice -p 'Password123!'
```

NTLM-backed recon:

```bash
./aydee --target 10.10.10.100 -d corp.local -u alice -H aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff
```

Kerberos-backed recon:

```bash
./aydee --target 10.10.10.100 -d corp.local -u alice -k --ccache ./alice.ccache
```

BloodHound only:

```bash
./aydee --target 10.10.10.100 -d corp.local -u alice -p 'Password123!' --only bloodhound
```

Conservative mode:

```bash
./aydee --target 10.10.10.100 --mode semi
```

Manual module selection:

```bash
./aydee --target 10.10.10.100 --mode manual --only dns,ldap,ldap-auth,smb-auth,credential
```

Password spray with explicit candidate:

```bash
./aydee --target 10.10.10.100 -d corp.local --mode manual --only spray --spray-passwords 'Winter2025!' --userlist ./users.txt
```

## Core Options

- `--target <TARGET>` target IP or hostname
- `-d, --domain <DOMAIN>` optional domain hint
- `-u, --username <USERNAME>` username
- `-p, --password <PASSWORD>` password
- `-H, --ntlm <NTLM>` NTLM hash
- `-k, --kerberos` enable Kerberos auth mode for supported collectors
- `--ccache <CCACHE>` set `KRB5CCNAME`
- `-m, --mode <MODE>` `auto`, `semi`, or `manual`
- `--only <MODULES>` module allowlist
- `--tags <TAGS>` tag filter for deeper checks
- `-P, --ports <PORTS>` custom port spec
- `--timeout <SECONDS>` TCP connect timeout
- `--collection <COLLECTION>` BloodHound collection scope
- `--non-interactive` suppress prompts
- `-o, --output <DIR>` custom output directory
- `--report-json <PATH>` JSON report path
- `--report-text <PATH>` text summary path
- `--manifest-json <PATH>` workspace manifest path

## Modules

- `scan`
- `dns`
- `ldap`
- `ldap-auth`
- `smb`
- `smb-auth`
- `rpc`
- `winrm`
- `kerberos`
- `credential`
- `bloodhound`
- `attacks`
- `spray`

## Output

By default each run creates:

```text
results/<target>_<unix_timestamp>/
```

Typical artifacts include:

- `aydee_report.json`
- `aydee_summary.txt`
- `aydee_report.html`
- `workspace_manifest.json`
- `bloodhound_output/`
- `kerberoast_hashes_*.txt`
- `asreproast_hashes_*.txt`
- recovered `.ccache` tickets from pre2k/default machine-account hits

## Notes

- `semi` mode skips noisier stages unless explicitly selected.
- `manual` mode requires `--only`.
- A Kerberos cache alone does not enable Kerberos auth paths; use `-k`.
- BloodHound is interactive by default in TTY sessions and auto-runs in non-interactive mode.
- Clock skew correction is attempted at startup unless `--no-fix-clock-skew` is set.
- Password spraying is opt-in only.

## Legal

Use only on infrastructure you own or are explicitly authorized to assess.
