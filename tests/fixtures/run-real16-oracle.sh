#!/usr/bin/env bash
set -euo pipefail

oracle=${1:-./oracle}
common=(
    "90" "89 D8" "66 89 D8"
    "8B 00" "67 8B 00" "26 8B 00"
    "8E D8" "0F 20 C0"
    "EA 34 12 78 56" "66 EA 78 56 34 12 BC 9A"
    "63 C0" "0F 00 C0" "0F 00 D0" "0F 02 C0" "0F 34"
    "C5 F8 77" "C4 E1 78 77" "62 F1 7C 48 58 C0" "8F E9 78 90 C0"
    "C4 00" "C5 00" "62 00" "8F 00"
    "0F 79 C0" "0F 79 00" "67 0F 79 C0" "67 0F 79 00"
    "0F 79 46 C0" "0F 79 86 C0 C0" "67 0F 79 44 24 C0"
    "-" "66" "0F" "C5" "EA 34"
)
relative=("EB FE" "E9 FE FF" "66 E9 FC FF FF FF" "67 E2 FE" "C7 F8 00 00")
prefixed=(
    "66 EB FE" "F2 EB FE" "2E EB FE" "67 E3 FE"
    "66 E8 FC FF FF FF" "66 0F 84 FF FF FF FF" "66 C7 F8 00 00 00 00"
)

for mode in real compat; do
    for syntax in intel att; do
        for bytes in "${common[@]}"; do
            printf '%s %s 0 %s: ' "$mode" "$syntax" "$bytes"
            "$oracle" "$mode" "$syntax" 0 "$bytes"
        done
        for address in 0 0xFFFF 0x10000; do
            for bytes in "${relative[@]}"; do
                printf '%s %s %s %s: ' "$mode" "$syntax" "$address" "$bytes"
                "$oracle" "$mode" "$syntax" "$address" "$bytes"
            done
        done
        for bytes in "${prefixed[@]}"; do
            printf '%s %s 0x10000 %s: ' "$mode" "$syntax" "$bytes"
            "$oracle" "$mode" "$syntax" 0x10000 "$bytes"
        done
    done
done
