use crate::byte_manipulation::u8_array_to_u32_le;

#[derive(Debug)]
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    /// Returns a new instance of ChaCha20
    ///
    /// # Panics
    ///
    /// The function will panic if `key` is not of size 32
    /// The function will panic if `nonce` is not of size 12
    pub fn new(key: &[u8], nonce: &[u8], counter: u32) -> ChaCha20 {
        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 12);

        let mut state = [0u32; 16];

        // Set constant
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Set key
        for i in 0..2 {
            for j in 0..4 {
                let array_start_offset = (i * 16) + (j * 4);
                let array_end_offset = array_start_offset + 4;

                state[4 + (i * 4) + j] = u8_array_to_u32_le(&key[array_start_offset..array_end_offset]);
            }
        }

        state[12] = counter;

        for i in 0..3 {
            let array_start_offset = i * 4;
            let array_end_offset = array_start_offset + 4;

            state[13 + i] = u8_array_to_u32_le(&nonce[array_start_offset..array_end_offset])
        }

        ChaCha20 { state }
    }

    /// Returns a length 32 array of `u8` from a `str`.
    ///
    /// If the key is smaller than 32 bytes it will append null bytes.
    /// If the key is over 32 bytes long it will trim it to 32 bytes.
    pub fn create_key(key: &str) -> [u8; 32] {
        let input_bytes = key.as_bytes();
        let mut key = [0u8; 32];

        for i in 0..32 {
            if input_bytes.len() > i {
                key[i] = input_bytes[i];
            }
        }

        key
    }

    /// Returns a length 12 array of `u8` from a `str`.
    ///
    /// If the key is smaller than 12 bytes it will append null bytes.
    /// If the key is over 12 bytes long it will trim it to 12 bytes.
    pub fn create_nonce(nonce: &str) -> [u8; 12] {
        let input_bytes = nonce.as_bytes();
        let mut nonce = [0u8; 12];

        for i in 0..12 {
            if input_bytes.len() > i {
                nonce[i] = input_bytes[i];
            }
        }

        nonce
    }

    /// Computes and returns the next ChaCha20 state
    pub fn next(&mut self) -> [u32; 16] {
        let next_state = self.block();

        // Update counter
        self.state[12] = self.state[12].wrapping_add(1);

        next_state
    }

    /// Single ChaCha20 round
    fn round(state: &mut [u32; 16], vector: (usize, usize, usize, usize)) {
        let (a, b, c, d) = vector;

        state[a] = state[a].wrapping_add(state[b]);
        state[d] = ChaCha20::rotate_left(state[d] ^ state[a], 16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = ChaCha20::rotate_left(state[b] ^ state[c], 12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] = ChaCha20::rotate_left(state[d] ^ state[a], 8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = ChaCha20::rotate_left(state[b] ^ state[c], 7);
    }

    /// ChaCha20 block function
    fn block(&mut self) -> [u32; 16] {
        let mut working_state = self.state.clone();

        for _ in 0..10 {
            ChaCha20::round(&mut working_state, (0, 4, 8, 12));  // col 0
            ChaCha20::round(&mut working_state, (1, 5, 9, 13));  // col 1
            ChaCha20::round(&mut working_state, (2, 6, 10, 14)); // col 2
            ChaCha20::round(&mut working_state, (3, 7, 11, 15)); // col 3

            ChaCha20::round(&mut working_state, (0, 5, 10, 15)); // diagonal 0
            ChaCha20::round(&mut working_state, (1, 6, 11, 12)); // diagonal 1
            ChaCha20::round(&mut working_state, (2, 7, 8, 13));  // diagonal 2
            ChaCha20::round(&mut working_state, (3, 4, 9, 14));  // diagonal 3
        }

        for (i, value) in self.state.iter().enumerate() {
            working_state[i] = working_state[i].wrapping_add(*value);
        }

        working_state
    }

    /// Safe rotate left
    fn rotate_left(value: u32, shift: u32) -> u32 {
        (value << shift) | (value >> (32 - shift))
    }
}

/// Tests for ChaCha20
///
/// For more information about the tests see:
/// https://datatracker.ietf.org/doc/html/rfc7539
#[cfg(test)]
mod test {
    use super::*;

    fn format_expected(expected: [u8; 64]) -> [u32; 16] {
        let mut expected_formatted = [0u32; 16];

        for i in 0..16 {
            let array_start_offset = i * 4;
            let array_end_offset = array_start_offset + 4;

            expected_formatted[i] = u8_array_to_u32_le(&expected[array_start_offset..array_end_offset]);
        }

        expected_formatted
    }

    #[test]
    fn test_state() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ];

        let nonce = [
            0x00, 0x00, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        ];

        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
            0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
            0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
        ];

        let mut expected_formatted = format_expected(expected);
        let mut chacha20 = ChaCha20::new(&key, &nonce, 1);

        assert_eq!(chacha20.next(), expected_formatted);
    }

    #[test]
    fn test_multiple_states() {
        let mut state = ChaCha20::new(&[0; 32], &[0; 12], 0);

        let expected_state: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
            0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
            0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
            0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
            0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
            0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
            0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
        ];
        let expected_state = format_expected(expected_state);


        assert_eq!(
            state.next(),
            expected_state
        );

        let expected_state: [u8; 64] = [
            0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
            0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
            0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
            0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
            0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
            0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
            0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
            0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f
        ];
        let expected_state = format_expected(expected_state);

        assert_eq!(
            state.next(),
            expected_state
        );
    }
}
