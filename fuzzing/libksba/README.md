# libksba fuzzing

Fuzzing harnesses for **libksba** (GnuPG's ASN.1/X.509/CMS/OCSP/CRL parser).
Same machine setup as the libusb harness: AFL++ (CLASSIC + laf-intel), a CmpLog
sibling per harness, ASan + UBSan + signed-integer-overflow at `-O0 -g`.

Why libksba: hand-rolled DER parsing, tiny maintainer team, ubiquitous (every
GnuPG install), **not on OSS-Fuzz**, no fuzz harness in-tree. CRL and OCSP parsing
are reachable **remotely** through `dirmngr` (HTTP/LDAP fetch); cert and CMS
through `gpgsm`. Prior art: CVE-2022-3515 (integer overflow -> heap overflow).

## Harnesses

| harness      | public entrypoint                       | parsers driven                          |
|--------------|-----------------------------------------|-----------------------------------------|
| `fuzz_cert`  | `ksba_cert_init_from_mem` + accessors   | cert.c, dn.c, keyinfo.c, name.c, oid.c, time.c |
| `fuzz_crl`   | `ksba_crl_set_reader` + `ksba_crl_parse`| crl.c, ber-help.c, keyinfo.c, time.c    |
| `fuzz_ocsp`  | `ksba_ocsp_parse_response`              | ocsp.c, time.c                          |
| `fuzz_cms`   | `ksba_cms_set_reader_writer` + `ksba_cms_parse` | cms.c, cms-parser.c             |

Cert parsing is lazy, so `fuzz_cert` calls the full accessor set to force the
deep parse. All parsers funnel through the BER decoder (`ber-decoder.c`,
`ber-help.c`).

## Usage

```
bash setup.sh            # deps + AFL++ + instrumented libksba + harnesses + corpus
bash start-fuzzers.sh    # 8 instances in tmux (master + CmpLog secondary per harness)
bash start-fuzzers.sh --status
bash cleanup.sh          # kill + remove artifacts (flags: --keep-corpus --keep-source ...)
```

`setup.sh` flags: `--skip-deps` (deps already installed), `--skip-afl` (use a
system afl-clang-fast instead of building AFL++ from source).

Each harness builds three ways: `H` (AFL persistent), `H.cmplog` (CmpLog), and
`H.repro` (plain clang + ASan, reads files from argv) for crash triage:

```
./fuzz_crl.repro output/master_crl/crashes/id:000000*
```

## Target version

`setup.sh` defaults to libksba git tip (1.8.x) - bugs there are reportable
upstream immediately. The line distros ship for `dirmngr`/`gpgsm` is older and
missing the 1.7.0 hardening; to fuzz that instead:

```
LIBKSBA_TAG=libksba-1.6.6 bash setup.sh
```

## Soft spots flagged during the audit (corpus is seeded toward these)

- `time.c` `_ksba_asntime_to_iso`: terminator check reads one byte past the time
  value when it has no trailing `Z`. Shared by cert/crl/ocsp time fields.
- `dn.c` `append_ucs2_value` / `append_ucs4_value`: odd-length BMPString /
  misaligned UniversalString over-read in subject/issuer DN.

These are 1-byte over-reads that land in decoder slack as shipped; the point of
fuzzing is to find the variant that doesn't.

## Notes

- The `#include`-the-`.c` trick used for libusb is not needed here: the bugs are
  reachable through the public API, so harnesses link the instrumented
  `libksba.a` and drive it normally.
- `gen_corpus.sh` mints real DER seeds with a throwaway openssl mini-CA
  (`conf/ca.cnf`): cert, empty + revoked CRL, signed CMS, OCSP response.
- LLVM-18 caveat carried from libusb: `AFL_LLVM_LAF_ALL=1` needs
  `AFL_LLVM_INSTRUMENT=CLASSIC` (PCGUARD miscompiles split comparisons).
