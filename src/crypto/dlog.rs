use super::{G, Scalar};
use anyhow::{Result, anyhow};
use group::Group;
use std::collections::HashMap;

/// Compute the discrete log of a group element.
pub fn compute_dlog(g: &G, challenge: &G, max_dlog: u64) -> Result<u64> {
    if max_dlog > (u64::MAX >> 4) {
        return Err(anyhow!("max_dlog is too large"));
    }

    let m = ((max_dlog as f64).sqrt().ceil() as u64) + 1;
    let m_scalar = Scalar::from(m);

    // Compute giant steps table: g^(m*i) for i in 0..m
    let mut giant_steps: HashMap<Vec<u8>, u64> = HashMap::with_capacity(m as usize);
    let giant_step = *g * m_scalar;
    let mut curr = G::identity();

    // Compute g^(m*i) for i in 0..m
    for i in 0..m {
        let curr_bytes = curr.compress().to_bytes().as_ref().to_vec();
        giant_steps.insert(curr_bytes, i * m);
        curr += giant_step;
    }

    // Compute challenge * g^j for j in 0..m
    let mut guess = *challenge;
    for j in 0..m {
        let guess_bytes = guess.compress().to_bytes().as_ref().to_vec();
        if let Some(&i) = giant_steps.get(&guess_bytes) {
            let res = i - j;
            if res <= max_dlog {
                return Ok(res);
            }
        }
        guess += *g;
    }
    Err(anyhow!("discrete log not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlog() {
        let g = G::generator();

        // Test small values
        let max_dlog = 1000;
        for x in [0u64, 1u64, 5u64, 42u64, 999u64].iter() {
            let scalar = Scalar::from(*x);
            let output = g * scalar;

            // Test post_process
            let result = compute_dlog(&g, &output, max_dlog).unwrap();
            assert_eq!(result, *x);
        }

        // Test large values
        let n_big = u32::MAX as u64;
        let scalar = Scalar::from(n_big - 1);
        let result = compute_dlog(&g, &(g * scalar), n_big).unwrap();
        assert_eq!(result, n_big - 1);

        // Test value outside range
        let scalar_out = Scalar::from(1001u64);
        assert!(compute_dlog(&g, &(g * scalar_out), max_dlog).is_err());
    }
}
