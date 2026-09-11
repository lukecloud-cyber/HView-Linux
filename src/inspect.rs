/*
This module provides bounded byte inspectors for the buffered workbench.
Each result keeps its source offset so the shared browser can return to the selected bytes.
*/
use crate::analysis::{Outcome, Progress, WINDOW_BYTES};

/*
String rows keep a fixed display prefix while scanning can continue through a longer source run.
*/
const TEXT_LIMIT: usize = 120;

/*
This predicate accepts the printable ASCII range used by both ASCII and UTF-16 string scans.
*/
fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

/*
This inspector finds printable ASCII and ASCII characters stored as UTF-16LE or UTF-16BE.
The minimum length and result limit bound accepted rows. Final sorting restores source order across encoding passes.
*/
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

    /*
    The second pass reads complete pairs in either byte order.
    It counts complete printable characters and stores only the bounded display prefix.
    */
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
    /*
    Both encoding passes can find rows in different source regions.
    Sorting and truncation produce one stable bounded browser result.
    */
    rows.sort_by_key(|row| row.0);
    rows.truncate(limit);
    rows
}

/*
This test wrapper runs the cancellable entropy implementation to completion.
It keeps the original synchronous result contract for direct equivalence tests.
*/
#[cfg(test)]
pub fn entropy_map(data: &[u8], block_size: usize) -> Vec<(usize, String)> {
    match entropy_map_cancellable(data, block_size, |_| true) {
        Outcome::Completed(rows) => rows,
        Outcome::Canceled => Vec::new(),
    }
}

/*
This inspector calculates Shannon entropy for each selected block.
Histogram counting uses work windows of at most 64 KiB and reports progress after each window.
The function returns no partial rows when the caller requests cancellation at any progress boundary.
*/
pub(crate) fn entropy_map_cancellable(
    data: &[u8],
    block_size: usize,
    mut progress: impl FnMut(Progress) -> bool,
) -> Outcome<Vec<(usize, String)>> {
    let block_size = block_size.max(1);
    let total = data.len() as u64;
    if !progress(Progress::new(0, total)) {
        return Outcome::Canceled;
    }
    let mut rows = Vec::with_capacity(data.len().div_ceil(block_size));
    let mut completed = 0usize;
    for (index, block) in data.chunks(block_size).enumerate() {
        /*
        Each block owns one histogram. Smaller work windows provide cooperative cancellation inside large blocks.
        */
        let mut counts = [0usize; 256];
        for window in block.chunks(WINDOW_BYTES) {
            for &byte in window {
                counts[byte as usize] += 1;
            }
            completed += window.len();
            if !progress(Progress::new(completed as u64, total)) {
                return Outcome::Canceled;
            }
        }

        /*
        This calculation converts the completed histogram into bits per byte and a fixed 16-cell bar.
        The row enters result storage only after its complete block has passed cancellation checks.
        */
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
        rows.push((
            index * block_size,
            format!(
                "{} {}  {:.3} bits/byte  [{}{}]",
                block.len(),
                if block.len() == 1 { "byte" } else { "bytes" },
                entropy,
                "#".repeat(filled),
                ".".repeat(16 - filled)
            ),
        ));
    }
    Outcome::Completed(rows)
}

/*
This inspector interprets complete integer widths at one selected source offset.
The optional byte order filters multi-byte rows, while the one-byte row stays byte-order independent.
*/
pub fn integers(
    data: &[u8],
    offset: usize,
    byte_order: Option<crate::editor::ByteOrder>,
) -> Vec<String> {
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
    /*
    This local generator applies the same complete-slice and byte-order rules to each integer width.
    Signed display reinterprets the exact unsigned bit pattern without changing source bytes.
    */
    macro_rules! integer {
        ($size:literal, $unsigned:ty, $signed:ty) => {
            if let Some(bytes) = tail.get(..$size) {
                let bytes: [u8; $size] = bytes.try_into().unwrap();
                for (selected_order, order, value) in [
                    (
                        crate::editor::ByteOrder::Little,
                        "LE",
                        <$unsigned>::from_le_bytes(bytes),
                    ),
                    (
                        crate::editor::ByteOrder::Big,
                        "BE",
                        <$unsigned>::from_be_bytes(bytes),
                    ),
                ] {
                    if byte_order.is_none_or(|selected| selected == selected_order) {
                        rows.push(format!(
                            "{}-bit {order}: unsigned {value}, signed {}, hex {:0width$X}",
                            $size * 8,
                            value as $signed,
                            value,
                            width = $size * 2
                        ));
                    }
                }
            }
        };
    }
    integer!(2, u16, i16);
    integer!(4, u32, i32);
    integer!(8, u64, i64);
    rows
}

/*
These tests verify encoding order, display bounds, cancellable entropy, and integer interpretation.
Each fixture uses deterministic bytes and exact expected result text.
*/
#[cfg(test)]
mod tests {
    use super::*;

    /*
    This test finds all supported string encodings and keeps their source order.
    */
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

    /*
    This test scans long runs without duplicate row starts and clips only displayed text.
    */
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

    /*
    This test checks exact entropy rows for empty, constant, uniform, tail, zero-size, and oversized blocks.
    Independent expected text protects the established result format.
    */
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

        assert_eq!(
            entropy_map_cancellable(&[], 0, |_| true),
            Outcome::Completed(Vec::new())
        );
        assert_eq!(
            entropy_map_cancellable(&[0, 0, 0, 0, 0, 1], 4, |_| true),
            Outcome::Completed(vec![
                (0, "4 bytes  0.000 bits/byte  [................]".into()),
                (4, "2 bytes  1.000 bits/byte  [##..............]".into()),
            ])
        );
        assert_eq!(
            entropy_map_cancellable(&[1, 2], 0, |_| true),
            Outcome::Completed(vec![
                (0, "1 byte  0.000 bits/byte  [................]".into()),
                (1, "1 byte  0.000 bits/byte  [................]".into()),
            ])
        );
        assert_eq!(
            entropy_map_cancellable(&[0, 1, 0, 1], usize::MAX, |_| true),
            Outcome::Completed(vec![(
                0,
                "4 bytes  1.000 bits/byte  [##..............]".into(),
            )])
        );
    }

    /*
    This test refuses work before counting, inside a large block, and at its final checkpoint.
    Every refusal returns Canceled without exposing a partial result vector.
    */
    #[test]
    fn entropy_cancellation_never_returns_partial_rows() {
        let data = vec![0x55; WINDOW_BYTES + 1];
        assert_eq!(
            entropy_map_cancellable(&data, data.len(), |_| false),
            Outcome::Canceled
        );
        let mut updates = Vec::new();
        assert_eq!(
            entropy_map_cancellable(&data, data.len(), |progress| {
                updates.push(progress);
                progress.completed < WINDOW_BYTES as u64
            }),
            Outcome::Canceled
        );
        assert_eq!(
            updates,
            [
                Progress::new(0, data.len() as u64),
                Progress::new(WINDOW_BYTES as u64, data.len() as u64),
            ]
        );
        let mut final_calls = 0;
        assert_eq!(
            entropy_map_cancellable(&[1, 2], 2, |progress| {
                final_calls += 1;
                progress.completed < progress.total
            }),
            Outcome::Canceled
        );
        assert_eq!(final_calls, 2);
    }

    /*
    This test checks signed, unsigned, endian, and unavailable-width integer rows.
    */
    #[test]
    fn integers_handle_endianness_signed_values_and_bounds() {
        let data = [0xff, 0x80, 0, 0, 0, 0, 0, 0];
        let rows = integers(&data, 0, None);
        assert_eq!(rows.len(), 7);
        assert_eq!(rows[0], "8-bit: unsigned 255, signed -1, hex FF");
        assert_eq!(
            rows[1],
            "16-bit LE: unsigned 33023, signed -32513, hex 80FF"
        );
        assert_eq!(rows[2], "16-bit BE: unsigned 65408, signed -128, hex FF80");
        assert!(rows[6].contains("signed -36028797018963968"));
        assert_eq!(
            integers(&data, 0, Some(crate::editor::ByteOrder::Little)).len(),
            4
        );
        assert_eq!(
            integers(&data, 0, Some(crate::editor::ByteOrder::Big)).len(),
            4
        );
        assert_eq!(integers(&[1, 2, 3], 2, None).len(), 1);
        assert!(integers(&[1], 1, None).is_empty());
        assert!(integers(&[1], usize::MAX, None).is_empty());
    }
}
