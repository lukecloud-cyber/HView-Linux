const TEXT_LIMIT: usize = 120;

fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

/// Return printable ASCII and ASCII characters encoded as UTF-16.
pub fn strings(data: &[u8], min_len: usize, limit: usize) -> Vec<(usize, String)> {
    if limit == 0 {
        return Vec::new();
    }
    let min_len = min_len.max(1);
    let mut rows = Vec::new();
    let mut offset = 0;
    while offset < data.len() && rows.len() < limit {
        let start = offset;
        while offset < data.len() && printable(data[offset]) {
            offset += 1;
        }
        let length = offset - start;
        if length >= min_len {
            let text = String::from_utf8_lossy(&data[start..start + length.min(TEXT_LIMIT)]);
            let suffix = if length > TEXT_LIMIT { "..." } else { "" };
            rows.push((start, format!("ASCII: {text}{suffix}")));
        }
        if offset == start {
            offset += 1;
        }
    }

    let ascii_count = rows.len();
    offset = 0;
    while offset < data.len().saturating_sub(1) && rows.len() - ascii_count < limit {
        let little = printable(data[offset]) && data[offset + 1] == 0;
        let big = data[offset] == 0 && printable(data[offset + 1]);
        if !little && !big {
            offset += 1;
            continue;
        }
        let start = offset;
        let mut text = String::new();
        let mut length = 0;
        while offset < data.len().saturating_sub(1) {
            let (byte, zero) = if little {
                (data[offset], data[offset + 1])
            } else {
                (data[offset + 1], data[offset])
            };
            if zero != 0 || !printable(byte) {
                break;
            }
            if length < TEXT_LIMIT {
                text.push(byte as char);
            }
            length += 1;
            offset += 2;
        }
        if length >= min_len {
            if length > TEXT_LIMIT {
                text.push_str("...");
            }
            let encoding = if little { "UTF-16LE" } else { "UTF-16BE" };
            rows.push((start, format!("{encoding}: {text}")));
        }
    }
    rows.sort_by_key(|row| row.0);
    rows.truncate(limit);
    rows
}

/// Return Shannon entropy in bits per byte. A zero block size uses one byte.
pub fn entropy_map(data: &[u8], block_size: usize) -> Vec<(usize, String)> {
    let block_size = block_size.max(1);
    data.chunks(block_size)
        .enumerate()
        .map(|(index, block)| {
            let mut counts = [0usize; 256];
            for &byte in block {
                counts[byte as usize] += 1;
            }
            let entropy = counts
                .iter()
                .filter(|&&count| count != 0)
                .map(|&count| {
                    let probability = count as f64 / block.len() as f64;
                    -probability * probability.log2()
                })
                .sum::<f64>()
                .abs();
            let filled = (entropy * 2.0).round().clamp(0.0, 16.0) as usize;
            (
                index * block_size,
                format!(
                    "{} {}  {:.3} bits/byte  [{}{}]",
                    block.len(),
                    if block.len() == 1 { "byte" } else { "bytes" },
                    entropy,
                    "#".repeat(filled),
                    ".".repeat(16 - filled)
                ),
            )
        })
        .collect()
}

/// Return integer values that fit at the selected offset.
pub fn integers(data: &[u8], offset: usize) -> Vec<String> {
    let Some(tail) = data.get(offset..) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    if let Some(&byte) = tail.first() {
        rows.push(format!(
            "8-bit: unsigned {byte}, signed {}, hex {byte:02X}",
            byte as i8
        ));
    }
    macro_rules! integer {
        ($size:literal, $unsigned:ty, $signed:ty) => {
            if let Some(bytes) = tail.get(..$size) {
                let bytes: [u8; $size] = bytes.try_into().unwrap();
                for (order, value) in [
                    ("LE", <$unsigned>::from_le_bytes(bytes)),
                    ("BE", <$unsigned>::from_be_bytes(bytes)),
                ] {
                    rows.push(format!(
                        "{}-bit {order}: unsigned {value}, signed {}, hex {:0width$X}",
                        $size * 8,
                        value as $signed,
                        value,
                        width = $size * 2
                    ));
                }
            }
        };
    }
    integer!(2, u16, i16);
    integer!(4, u32, i32);
    integer!(8, u64, i64);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_detect_encodings_and_keep_file_order() {
        let data = b"\xffA\0B\0C\0\xffplain\xff\0D\0E\0F\xff";
        let rows = strings(data, 3, 20);
        assert_eq!(
            rows,
            vec![
                (1, "UTF-16LE: ABC".into()),
                (8, "ASCII: plain".into()),
                (14, "UTF-16BE: DEF".into()),
            ]
        );
        assert_eq!(strings(data, 3, 1), rows[..1]);
        assert!(strings(data, 3, 0).is_empty());
        assert!(strings(&[], 0, 10).is_empty());
    }

    #[test]
    fn strings_consume_long_runs_without_duplicate_starts() {
        let mut data = vec![b'x'; 200];
        data.push(0xff);
        for _ in 0..200 {
            data.extend([0, b'y']);
        }
        data.extend([0xff, b'z']);
        let rows = strings(&data, 3, 10);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            (0, format!("ASCII: {}...", "x".repeat(TEXT_LIMIT)))
        );
        assert_eq!(
            rows[1],
            (201, format!("UTF-16BE: {}...", "y".repeat(TEXT_LIMIT)))
        );
        assert_eq!(strings(b"A\0B\0C\0", 3, 10).len(), 1);
        assert_eq!(strings(b"\0A\0B\0C", 3, 10).len(), 1);
    }

    #[test]
    fn entropy_matches_constant_and_uniform_data() {
        assert!(entropy_map(&[], 0).is_empty());
        let mut data = vec![0; 256];
        data.extend(0..=255);
        data.push(0);
        let rows = entropy_map(&data, 256);
        assert_eq!(
            rows[0],
            (0, "256 bytes  0.000 bits/byte  [................]".into())
        );
        assert_eq!(
            rows[1],
            (256, "256 bytes  8.000 bits/byte  [################]".into())
        );
        assert_eq!(rows[2].0, 512);
        assert!(rows[2].1.starts_with("1 byte  0.000"));
        assert_eq!(entropy_map(&[1, 2], 0).len(), 2);
    }

    #[test]
    fn integers_handle_endianness_signed_values_and_bounds() {
        let rows = integers(&[0xff, 0x80, 0, 0, 0, 0, 0, 0], 0);
        assert_eq!(rows.len(), 7);
        assert_eq!(rows[0], "8-bit: unsigned 255, signed -1, hex FF");
        assert_eq!(
            rows[1],
            "16-bit LE: unsigned 33023, signed -32513, hex 80FF"
        );
        assert_eq!(rows[2], "16-bit BE: unsigned 65408, signed -128, hex FF80");
        assert!(rows[6].contains("signed -36028797018963968"));
        assert_eq!(integers(&[1, 2, 3], 2).len(), 1);
        assert!(integers(&[1], 1).is_empty());
        assert!(integers(&[1], usize::MAX).is_empty());
    }
}
