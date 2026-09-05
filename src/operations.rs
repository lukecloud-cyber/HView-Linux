pub struct Pattern {
    bytes: Vec<(u8, u8)>,
}

pub fn parse_pattern(text: &str) -> Result<Pattern, String> {
    let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err("Enter complete hex byte pairs. Use ? for a wildcard nibble.".into());
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_chunks::<2>().0 {
        let mut value = 0;
        let mut mask = 0;
        for digit in pair {
            value <<= 4;
            mask <<= 4;
            if *digit != '?' {
                value |= digit
                    .to_digit(16)
                    .ok_or("The pattern contains an invalid hex digit.")?
                    as u8;
                mask |= 0x0f;
            }
        }
        bytes.push((value, mask));
    }
    Ok(Pattern { bytes })
}

impl Pattern {
    pub fn exact(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Enter at least one search byte.".into());
        }
        Ok(Self {
            bytes: bytes.into_iter().map(|byte| (byte, 0xff)).collect(),
        })
    }

    pub fn find(&self, data: &[u8], start: usize, backward: bool) -> Option<usize> {
        let last = data.len().checked_sub(self.bytes.len())?;
        let matches = |offset: &usize| {
            self.bytes
                .iter()
                .zip(&data[*offset..])
                .all(|(&(value, mask), &byte)| byte & mask == value)
        };
        if backward {
            (0..=start.min(last)).rev().find(matches)
        } else {
            (start..=last).find(matches)
        }
    }
}

pub fn differences(left: &[u8], right: &[u8], limit: usize) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let mut offset = 0;
    let end = left.len().max(right.len());
    while offset < end && result.len() < limit {
        if left.get(offset) == right.get(offset) {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < end && left.get(offset) != right.get(offset) {
            offset += 1;
        }
        let preview = |data: &[u8]| {
            let bytes = &data[start.min(data.len())..offset.min(data.len())];
            if bytes.is_empty() {
                return "<absent>".to_string();
            }
            let mut text = bytes
                .iter()
                .take(8)
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            if bytes.len() > 8 {
                text.push_str(" ...");
            }
            text
        };
        result.push((
            start,
            format!(
                "{} {}: old [{}], new [{}]",
                offset - start,
                if offset - start == 1 { "byte" } else { "bytes" },
                preview(left),
                preview(right)
            ),
        ));
    }
    result
}

pub fn transform(
    data: &mut [u8],
    start: usize,
    len: usize,
    mask: &[u8],
    xor: bool,
) -> Result<(), String> {
    if len == 0 {
        return Err("The block length must be greater than zero.".into());
    }
    if mask.is_empty() {
        return Err("Enter at least one mask byte.".into());
    }
    let end = start
        .checked_add(len)
        .filter(|&end| end <= data.len())
        .ok_or("The block extends past the file end.")?;
    for (index, byte) in data[start..end].iter_mut().enumerate() {
        if xor {
            *byte ^= mask[index % mask.len()];
        } else {
            *byte = mask[index % mask.len()];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_search_checks_nibbles_and_boundaries() {
        let pattern = parse_pattern("a? ?F\t??").unwrap();
        let data = [0xaf, 0x01, 0xff, 0xa2, 0x3f, 0, 0xab, 0xff, 0x12];
        assert_eq!(pattern.find(&data, 0, false), Some(3));
        assert_eq!(pattern.find(&data, 3, false), Some(3));
        assert_eq!(pattern.find(&data, 4, false), Some(6));
        assert_eq!(pattern.find(&data, 7, false), None);
        assert_eq!(pattern.find(&data, usize::MAX, false), None);
        assert_eq!(pattern.find(&data, usize::MAX, true), Some(6));
        assert_eq!(pattern.find(&data, 5, true), Some(3));
        assert_eq!(pattern.find(&data, 2, true), None);
        assert_eq!(pattern.find(&data[..2], 0, true), None);
        assert_eq!(
            parse_pattern("a??f??").unwrap().find(&data, 0, false),
            Some(3)
        );
        for text in ["", "  ", "?", "ABC", "GG", "0xAA", "AA-Z"] {
            assert!(parse_pattern(text).is_err(), "{text}");
        }
    }

    #[test]
    fn exact_search_handles_zero_bytes_and_overlapping_matches() {
        assert!(Pattern::exact(Vec::new()).is_err());
        let pattern = Pattern::exact(vec![0, 0]).unwrap();
        assert_eq!(pattern.find(&[0, 0, 0], 1, false), Some(1));
        assert_eq!(pattern.find(&[0, 0, 0], 0, true), Some(0));
        assert_eq!(pattern.find(&[], 0, false), None);
    }

    #[test]
    fn comparison_groups_changes_and_length_only_tails() {
        let result = differences(&[1, 2, 3, 4], &[1, 9, 8, 4, 5], 10);
        assert_eq!(
            result,
            vec![
                (1, "2 bytes: old [02 03], new [09 08]".into()),
                (4, "1 byte: old [<absent>], new [05]".into()),
            ]
        );
        assert_eq!(
            differences(&[1, 2], &[1], 1)[0].1,
            "1 byte: old [02], new [<absent>]"
        );
        assert_eq!(differences(&[1], &[2], 0), Vec::new());
        assert_eq!(differences(&[], &[], 10), Vec::new());
        assert_eq!(differences(&[1, 2], &[1, 2], 10), Vec::new());
        assert_eq!(differences(&[1, 0, 1], &[2, 0, 2], 1).len(), 1);
        assert_eq!(
            differences(&[], &[0; 9], 1)[0].1,
            "9 bytes: old [<absent>], new [00 00 00 00 00 00 00 00 ...]"
        );
    }

    #[test]
    fn transforms_repeat_masks_and_reject_invalid_ranges_without_changes() {
        let original = [1, 2, 3, 4, 5, 6];
        let mut data = original;
        transform(&mut data, 1, 4, &[0xff, 0x10], true).unwrap();
        assert_eq!(data, [1, 0xfd, 0x13, 0xfb, 0x15, 6]);
        transform(&mut data, 1, 4, &[0xff, 0x10], true).unwrap();
        assert_eq!(data, original);
        transform(&mut data, 2, 4, &[0xaa, 0xbb, 0xcc], false).unwrap();
        assert_eq!(data, [1, 2, 0xaa, 0xbb, 0xcc, 0xaa]);
        let unchanged = data;
        for (start, len, mask) in [
            (0, 0, &[1][..]),
            (0, 1, &[][..]),
            (5, 2, &[1][..]),
            (6, 1, &[1][..]),
            (usize::MAX, 2, &[1][..]),
            (2, usize::MAX, &[1][..]),
        ] {
            assert!(transform(&mut data, start, len, mask, false).is_err());
            assert_eq!(data, unchanged);
        }
        assert!(transform(&mut [], 0, 1, &[1], true).is_err());
    }
}
