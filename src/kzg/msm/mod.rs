//! Utilities and tests for multi-scalar multiplication.
pub mod stream_pippenger;
pub mod variable_base;

pub use stream_pippenger::*;

fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)
    (ark_std::log2(a) * 69 / 100) as usize
}

fn bounded_ln_without_floats(a: usize, max_msm_buffer_log: usize) -> usize {
    if a < 32 {
        3
    } else {
        // in theory, we cannot store more than log memory.
        // Hence, we cap the number of buckets to avoid flooding memory.
        let optimal_size = ln_without_floats(a);
        if optimal_size > max_msm_buffer_log {
            max_msm_buffer_log
        } else {
            optimal_size
        }
    }
}
