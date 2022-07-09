pub(crate) const EMPTY_NONCE: [u8; 12] = [0; 12];

pub(crate) fn xor(output: &mut [u8], other: &[u8]) {
    for i in 0..output.len() {
        output[i] = output[i] ^ other[i];
    }
}
