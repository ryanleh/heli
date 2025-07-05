use anyhow::{Result, anyhow};
use group::{Group, GroupEncoding};
use std::collections::HashMap;

pub fn compute_dlog<G: Group + GroupEncoding>(g: &G, challenge: &G, max_dlog: u32) -> Result<u32> {
    if max_dlog > (u32::MAX >> 4) {
        return Err(anyhow!("max_dlog is too large"));
    }

    let m = ((max_dlog as f64).sqrt().ceil() as u32) + 1;
    let m_scalar = G::Scalar::from(m as u64);

    // Compute giant steps table: g^(m*i) for i in 0..m
    let mut giant_steps: HashMap<Vec<u8>, u32> = HashMap::with_capacity(m as usize);
    let giant_step = *g * m_scalar;
    let mut curr = G::identity();

    // Compute g^(m*i) for i in 0..m
    for i in 0..m {
        let curr_bytes = curr.to_bytes().as_ref().to_vec();
        giant_steps.insert(curr_bytes, i * m);
        curr += giant_step;
    }

    // Compute challenge * g^j for j in 0..m
    let mut guess = *challenge;
    for j in 0..m {
        let guess_bytes = guess.to_bytes().as_ref().to_vec();
        if let Some(&i) = giant_steps.get(&guess_bytes) {
            let res = i - j;
            if res < max_dlog {
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
    use curve25519_dalek::RistrettoPoint;

    #[test]
    fn test_compute_dlog() {
        type G = RistrettoPoint;
        let g = G::generator();
        let n = 1000;

        // Test finding discrete log for known values
        for x in [0u32, 1u32, 5u32, 42u32, 999u32].iter() {
            let scalar = <G as Group>::Scalar::from(*x as u64);
            let output = g * scalar;

            let result = compute_dlog(&g, &output, n).unwrap();
            assert_eq!(result, *x);
        }

        // Test value outside range
        let scalar = <G as Group>::Scalar::from(1000u64);
        let output = g * scalar;
        assert!(compute_dlog(&g, &output, n).is_err());

        // Test value outside range
        let scalar = <G as Group>::Scalar::from(10001u64);
        let output = g * scalar;
        assert!(compute_dlog(&g, &output, n).is_err());

        // Test large value near u32::MAX
        let scalar = <G as Group>::Scalar::from(((u32::MAX >> 8) - 6) as u64);
        let output = g * scalar;
        let n_big = (u32::MAX >> 8) - 1;
        assert_eq!(
            compute_dlog(&g, &output, n_big).unwrap(),
            (u32::MAX >> 8) - 6
        );
    }
}
