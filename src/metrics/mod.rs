#[cfg(any(test, feature = "metrics"))]
pub mod counters;

#[cfg(any(test, feature = "metrics"))]
#[inline(always)]
/// Increment the counter `JELLYFISH_INTERNAL_ENCODED_BYTES` by amount
/// if metrics are enabled. No-op otherwise
pub fn inc_internal_encoded_bytes_if_enabled(amount: usize) {
    use self::counters::JELLYFISH_INTERNAL_ENCODED_BYTES;

    JELLYFISH_INTERNAL_ENCODED_BYTES.inc_by(amount as u64)
}

#[cfg(not(any(test, feature = "metrics")))]
#[inline(always)]
/// Increment the counter `JELLYFISH_INTERNAL_ENCODED_BYTES` by amount
/// if metrics are enabled. No-op otherwise
pub fn inc_internal_encoded_bytes_if_enabled(amount: usize) {}
