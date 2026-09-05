# Test fixtures

These files contain controlled runtime output from the original reference program.
The test copies are separate from runtime probes because the original can rewrite a loaded save file.

| File | SHA-256 |
|---|---|
| offset-10.sav | 8E4AB80E5332DD1855B79DDFF16490E124340FFCFE63D2E6F25D56BD89063F31 |
| offset-20.sav | 51EFE5E51CC20803BEEC253CF655235541B48FB9E414360C12167392CC6AE6BE |

Both files use the compressed BLZ1 envelope.
The active file cursor is 0x10 or 0x20, respectively.
The files can contain additional history records from controlled restore tests.

The Windows DLL files verify the real PE browser against tracked upstream binaries.
The Linux package does not contain these Windows test fixtures.

| File | Version | SHA-256 |
|---|---|---|
| windows-capstone-5.0.9.dll | Capstone 5.0.9 | 76958E18380023A68FD1714FA2E01C594CC6DB1955A07AD6937B66E66DC5D6C3 |
| windows-keystone-0.9.2.dll | Keystone 0.9.2 | 3AC03927981FCA588C95B2CD1F2F1D64DC33DBD55B362FC7742163647746C3E8 |

The files came from the verified Windows PyPI wheels in the HView-windows source baseline.
