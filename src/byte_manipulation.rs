/// Return a u32 from a str in little endian format
///
/// # Panics
///
/// This code will panic if the string is not 4 bytes long
#[allow(dead_code)]
pub fn string_to_u32_le(string: &str) -> u32 {
    assert_eq!(string.bytes().len(), 4);

    let mut output = 0u32;
    for (i, byte) in string.bytes().enumerate() {
        output |= (0x000000FF << (i * 8)) & ((byte as u32) << (i * 8));
    }

    output
}

/// Returns a u32 from a u8 array in little endian format
///
/// # Panics
///
/// This code will panic if the u8 array is not of length 4
#[allow(dead_code)]
pub fn u8_array_to_u32_le(arr: &[u8]) -> u32 {
    assert_eq!(arr.len(), 4);

    let mut output = 0u32;
    output |= 0x000000FF & (arr[0] as u32);
    output |= 0x0000FF00 & ((arr[1] as u32) << 8);
    output |= 0x00FF0000 & ((arr[2] as u32) << 16);
    output |= 0xFF000000 & ((arr[3] as u32) << 24);

    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_converts_u8_array_to_u32() {
        let arr = [1u8, 1u8, 1u8, 1u8];
        assert_eq!(16843009, u8_array_to_u32_le(&arr));
    }

    #[test]
    fn it_converts_string_to_u32() {
        let str = "AAAA";
        assert_eq!(1094795585, string_to_u32_le(str));
    }
}