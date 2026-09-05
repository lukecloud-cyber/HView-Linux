# Real16 oracle evidence

This report records the temporary Zydis oracle used for the Real16 policy.
The application does not load or package Zydis.

## Provenance

- Zydis repository: `https://github.com/zyantific/zydis.git`
- Zydis commit: `1ba75aeefae37094c7be8eba07ff81d4fe0f1f20`
- Zycore submodule commit: `1401fb85ac313f6605ec795c52bf99ea3f292a69`
- Capstone package: 5.0.9
- Host: Linux x86-64

The temporary C harness called `ZydisDecoderDecodeFull`, `ZydisFormatterFormatInstruction`, and `ZydisCalcAbsoluteAddress`.
The harness compared `REAL_16` with `LONG_COMPAT_16`.
The harness ran each fixture with Intel and AT&T syntax.

## Build commands

```text
git clone --recurse-submodules https://github.com/zyantific/zydis.git /tmp/hview-zydis-oracle-1ba75a
git -C /tmp/hview-zydis-oracle-1ba75a checkout 1ba75aeefae37094c7be8eba07ff81d4fe0f1f20
git -C /tmp/hview-zydis-oracle-1ba75a submodule update --init --recursive
cc -std=c17 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -DZYDIS_STATIC_BUILD -DZYCORE_STATIC_BUILD -Iinclude -Isrc -Idependencies/zycore/include oracle.c src/*.c dependencies/zycore/src/*.c dependencies/zycore/src/API/*.c -pthread -o oracle
```

The build completed without a compiler warning.
The comparison ran 86 fixture, address, and syntax combinations against each decoder mode.

## Valid instruction results

| Bytes | Length | Operand width | Address width | Required result |
|---|---:|---:|---:|---|
| `90` | 1 | 16 | 16 | NOP |
| `89 D8` | 2 | 16 | 16 | AX and BX |
| `66 89 D8` | 3 | 32 | 16 | EAX and EBX |
| `8B 00` | 2 | 16 | 16 | Word through BX and SI |
| `67 8B 00` | 3 | 16 | 32 | Word through EAX |
| `26 8B 00` | 3 | 16 | 16 | Word through ES, BX, and SI |
| `8E D8` | 2 | 16 | 16 | DS and AX |
| `0F 20 C0` | 3 | 32 | 16 | EAX and CR0 |
| `EA 34 12 78 56` | 5 | 16 | 16 | Far target `5678:1234` |
| `66 EA 78 56 34 12 BC 9A` | 8 | 32 | 16 | Far target `9ABC:12345678` |

Intel and AT&T produced the same lengths, widths, registers, and numeric values.
The syntax setting changed only the formatted operand order and syntax marks.

## Relative target results

The harness ran each relative fixture at addresses `0`, `0xFFFF`, and `0x10000`.
The table shows the formatted Real16 target for those addresses.

| Bytes | Length | Address 0 | Address FFFF | Address 10000 |
|---|---:|---:|---:|---:|
| `EB FE` | 2 | `0000` | `FFFF` | `0000` |
| `E9 FE FF` | 3 | `0001` | `0000` | `0001` |
| `66 E9 FC FF FF FF` | 6 | `0002` | `0001` | `0002` |
| `67 E2 FE` | 3 | `0001` | `0000` | `0001` |
| `C7 F8 00 00` | 4 | `0004` | `0003` | `0004` |

Real16 wraps only direct relative targets to 16 bits.
Real16 does not change far-pointer segment or offset values.

## Validity results

Real16 rejected these protected-mode candidates.
LONG_COMPAT_16 and Capstone accepted each candidate.

```text
63 C0
0F 00 C0
0F 00 D0
0F 02 C0
0F 34
```

Real16 rejected these VEX, EVEX, and XOP candidates.
LONG_COMPAT_16 and Capstone accepted each candidate.

```text
C5 F8 77
C4 E1 78 77
62 F1 7C 48 58 C0
8F E9 78 90 C0
```

Real16 and Capstone accepted these two-byte legacy instructions.

| Bytes | Mnemonic |
|---|---|
| `C4 00` | LES |
| `C5 00` | LDS |
| `62 00` | BOUND |
| `8F 00` | POP |

Real16 rejected the empty input and these incomplete inputs: `66`, `0F`, `C5`, and `EA 34`.
The optional byte fallback advances one byte after each decoder error.

## Complete protected-mode policy

The pinned generated table marked these 41 unique mnemonics as protected-mode only.

```text
ARPL CLGI CLRSSBSY ENCLS ENCLU ENCLV GETSEC INCSSPD INVEPT INVLPGA INVVPID
LAR LLDT LSL LTR RSTORSSP SAVEPREVSSP SETSSBSY SKINIT SLDT STGI STR
SYSENTER SYSEXIT SYSRET VERR VERW VMCLEAR VMLAUNCH VMLOAD VMPTRLD VMPTRST
VMREAD VMRESUME VMRUN VMSAVE VMWRITE VMXOFF VMXON WRSSD WRUSSD
```

The extraction selected the first Boolean pair before each generated instruction category.
The extraction returned exactly 41 unique names.

```text
python3 -c 'from pathlib import Path; import re; text=Path("src/Generated/InstructionDefinitions.inc").read_text(); names=sorted(set(re.findall(r"ZYDIS_MNEMONIC_([A-Z0-9_]+).*?, ZYAN_TRUE, ZYAN_(?:FALSE|TRUE) ZYDIS_NOTMIN\\(ZYDIS_CATEGORY_", text))); print(len(names)); print(", ".join(names))'
```

The Real16 policy checks the canonical Capstone mnemonic against the complete set.
The vector check also uses the canonical mnemonic.
The vector check therefore preserves LES, LDS, BOUND, and POP.
The policy keeps MOV control-register instructions valid.
