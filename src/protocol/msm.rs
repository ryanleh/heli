use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use group::{Group, GroupEncoding};
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use subtle::{Choice, CtOption};

// TODO: This should be somewhere else
pub trait MSM {
    type Coeff; // Using `Coeff` to avoid conflict with Group
    type Point;

    /// Perform multi-scalar multiplication: sum_i scalars[i] * points[i]
    fn msm(scalars: &[Self::Coeff], points: &[Self::Point]) -> Self::Point;
}

// TODO: Use the multiexp library to implement this
//impl<G: Group + PrimeFieldBits + Zeroize> MSM for G

// A wrapper struct to allow us to use dalek's group type with MSMs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ristretto(pub RistrettoPoint);

impl Group for Ristretto {
    type Scalar = Scalar;

    fn random(mut rng: impl rand_core::RngCore) -> Self {
        // Use a different approach that doesn't require CryptoRng
        // Generate random bytes and convert to point
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        // This is a simplified approach - in practice you'd want proper point generation
        Ristretto(RistrettoPoint::from_uniform_bytes(&bytes))
    }

    fn identity() -> Self {
        Ristretto(RistrettoPoint::identity())
    }

    fn generator() -> Self {
        Ristretto(RistrettoPoint::generator())
    }

    fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    fn double(&self) -> Self {
        Ristretto(self.0.double())
    }
}

impl GroupEncoding for Ristretto {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        RistrettoPoint::from_bytes(bytes).map(Ristretto).into()
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        RistrettoPoint::from_bytes_unchecked(bytes)
            .map(Ristretto)
            .into()
    }

    fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
    }
}

// Implement Sum trait
impl std::iter::Sum for Ristretto {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Ristretto::identity(), |acc, x| acc + x)
    }
}

impl<'a> std::iter::Sum<&'a Ristretto> for Ristretto {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Ristretto::identity(), |acc, x| acc + x)
    }
}

impl MSM for Ristretto {
    type Coeff = Scalar;
    type Point = Ristretto;

    fn msm(scalars: &[Scalar], points: &[Ristretto]) -> Ristretto {
        // Extract inner points for Dalek's multiscalar_mul
        let inner_points = points.iter().map(|p| p.0);
        let result = RistrettoPoint::multiscalar_mul(scalars.iter(), inner_points);
        Ristretto(result)
    }
}

// Implement arithmetic operations
impl Add for Ristretto {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Ristretto(self.0 + other.0)
    }
}

impl Add<&Ristretto> for Ristretto {
    type Output = Self;
    fn add(self, other: &Self) -> Self {
        Ristretto(self.0 + other.0)
    }
}

impl AddAssign for Ristretto {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl AddAssign<&Ristretto> for Ristretto {
    fn add_assign(&mut self, other: &Self) {
        self.0 += other.0;
    }
}

impl Sub for Ristretto {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Ristretto(self.0 - other.0)
    }
}

impl Sub<&Ristretto> for Ristretto {
    type Output = Self;
    fn sub(self, other: &Self) -> Self {
        Ristretto(self.0 - other.0)
    }
}

impl SubAssign for Ristretto {
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl SubAssign<&Ristretto> for Ristretto {
    fn sub_assign(&mut self, other: &Self) {
        self.0 -= other.0;
    }
}

impl Neg for Ristretto {
    type Output = Self;
    fn neg(self) -> Self {
        Ristretto(-self.0)
    }
}

// Implement scalar multiplication
impl std::ops::Mul<Scalar> for Ristretto {
    type Output = Self;
    fn mul(self, scalar: Scalar) -> Self {
        Ristretto(self.0 * scalar)
    }
}

impl std::ops::Mul<&Scalar> for Ristretto {
    type Output = Self;
    fn mul(self, scalar: &Scalar) -> Self {
        Ristretto(self.0 * scalar)
    }
}

impl std::ops::MulAssign<Scalar> for Ristretto {
    fn mul_assign(&mut self, scalar: Scalar) {
        self.0 *= scalar;
    }
}

impl std::ops::MulAssign<&Scalar> for Ristretto {
    fn mul_assign(&mut self, scalar: &Scalar) {
        self.0 *= scalar;
    }
}
