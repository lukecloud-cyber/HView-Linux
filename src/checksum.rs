pub fn checksum(data: &[u8]) -> u32 {
    let full = data.len() & !3;
    let mut sum = 0u32;
    for byte in data[full..].iter().rev() {
        sum = sum.wrapping_shl(9).wrapping_add(u32::from(*byte));
    }
    sum = sum.wrapping_mul(8);
    for word in data[..full].as_chunks::<4>().0 {
        sum = sum
            .wrapping_add(sum.rotate_left(1))
            .wrapping_add(u32::from_le_bytes(*word));
    }
    sum
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_checksum_vectors() {
        assert_eq!(super::checksum(&[]), 0);
        assert_eq!(super::checksum(&[1, 0, 0, 0, 2, 0, 0, 0]), 5);
        assert_eq!(
            super::checksum(&[1, 2, 3]),
            ((3u32 << 18) + (2 << 9) + 1) * 8
        );
    }
}
