use rand::prelude::*;
use std::ops::{Add, Div, Mul, Rem, Sub};

// y^2 = x3 + 1x + 0
const PRIME: Scalar = Scalar(23);
const A: Scalar = Scalar(1);
const _B: Scalar = Scalar(0);
const N: Scalar = Scalar(23);
const G: Point = Point {
    x: Scalar(9),
    y: Scalar(5),
};
// (1,1), (1,6), (2,3), (2,4), (3,1), (3,6), (4,2), (4,5), (6,2), (6,5)

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Scalar(pub i32);

impl Scalar {
    fn binary(&self) -> Vec<bool> {
        let u = self.0 as u32;
        let u_str = format!("{:b}", u);
        let mut vec: Vec<bool> = vec![];
        for i in u_str.chars() {
            vec.push(i == '1');
        }
        vec
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Point {
    pub x: Scalar,
    pub y: Scalar,
}

// y^2 = x^3 + ax + b
#[derive(Default)]
pub struct Curve {
    p: Scalar,
    _a: Scalar,
    _b: Scalar,
    n: Scalar,
    _h: Scalar,
    g: Point,
}

pub type SecretKey = Scalar;
pub type PublicKey = Point;
pub type Signature = Point;

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Scalar) -> Self::Output {
        Scalar((self.0 + rhs.0) % PRIME.0)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Scalar) -> Self::Output {
        if self.0 >= other.0 {
            Scalar(self.0 - other.0)
        } else {
            Scalar(PRIME.0 - (other.0 - self.0))
        }
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Scalar(self.0 * rhs.0 % PRIME.0)
    }
}

impl Rem for Scalar {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        if self.0 < 0 {
            let tmp = self.0 % rhs.0;
            Scalar((rhs.0 + tmp) % rhs.0)
        } else {
            Scalar(self.0 % rhs.0)
        }
    }
}

impl Div for Scalar {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.mul_inverse()
    }
}

pub trait Inverse {
    fn add_inverse(&self) -> Self;

    fn mul_inverse(&self) -> Self;
}

impl Inverse for Point {
    fn add_inverse(&self) -> Point {
        Point {
            x: self.x,
            y: PRIME - self.y,
        }
    }

    fn mul_inverse(&self) -> Point {
        Default::default()
    }
}

fn extended_euclidean_algorithm(a: Scalar, b: Scalar) -> (Scalar, Scalar, Scalar) {
    let mut s = 0;
    let mut old_s = 1;
    let mut t = 1;
    let mut old_t = 0;
    let mut r = b.0;
    let mut old_r = a.0;

    while r != 0 {
        let quotient = old_r / r;
        let new_r = old_r - quotient * r;
        old_r = r;
        r = new_r;
        let new_s = old_s - quotient * s;
        old_s = s;
        s = new_s;
        let new_t = old_t - quotient * t;
        old_t = t;
        t = new_t;
    }

    (Scalar(old_r), Scalar(old_s), Scalar(old_t))
}

impl Inverse for Scalar {
    fn add_inverse(&self) -> Scalar {
        if self < &PRIME {
            *self
        } else {
            PRIME - *self
        }
    }

    fn mul_inverse(&self) -> Scalar {
        let (gcd, x, _y) = extended_euclidean_algorithm(*self, PRIME);
        if gcd != Scalar(1) {
            panic!("value {:?} has no multiplicative", self);
        }
        x % PRIME
    }
}

impl Add for Point {
    type Output = Self;

    fn add(self, rhs: Point) -> Self::Output {
        if rhs.x == Scalar(0) && rhs.y == Scalar(0) {
            return self;
        }

        let m = if self != rhs {
            (self.y - rhs.y) / (self.x - rhs.x)
        } else {
            (Scalar(3) * (self.x * self.x) + A) / (Scalar(2) * self.y)
        };

        let x = m * m - self.x - rhs.x;
        let y = self.y + m * (x - self.x);
        let tmp_y = Scalar(-y.0) % PRIME;

        Point { x: x, y: tmp_y }
    }
}

impl Mul<Point> for Scalar {
    type Output = Point;

    fn mul(self, rhs: Point) -> Self::Output {
        rhs * self
    }
}

impl Mul<Scalar> for Point {
    type Output = Self;

    // double and add
    fn mul(self, rhs: Scalar) -> Self::Output {
        let mut bin = rhs.binary();
        let mut last_point = Point {
            x: Scalar(0),
            y: Scalar(0),
        };
        let mut next_point = self;
        while bin.len() > 0 {
            let i = bin.pop().unwrap();
            if i {
                last_point = last_point + next_point;
            }
            next_point = next_point + next_point;
        }

        last_point
    }
}

impl Curve {
    pub fn new() -> Curve {
        Curve {
            p: PRIME,
            _a: A,
            _b: _B,
            n: N,
            _h: Scalar(1),
            g: G,
        }
    }

    pub fn random_number(&self) -> Scalar {
        Scalar(thread_rng().gen_range(1, self.n.0)) // random number in range (1, n)
    }

    pub fn generate_keypair(&self) -> (Scalar, Point) {
        let d = self.random_number();
        (d, d * self.g)
    }

    pub fn sign(&self, sk: SecretKey, z: Scalar) -> Signature {
        loop {
            let mut _k = Scalar(0);
            let mut _r = Scalar(0);

            loop {
                let tmp_k = self.random_number();
                let p = tmp_k * self.g;
                let tmp_r = p.x % self.p;
                if tmp_r == Scalar(0) {
                    continue;
                } else {
                    _r = tmp_r;
                    _k = tmp_k;
                    break;
                }
            }

            let s = _k.mul_inverse() * (z + _r * sk);
            if s == Scalar(0) {
                continue;
            } else {
                return Point { x: _r, y: s };
            }
        }
    }

    pub fn verify(&self, pk: PublicKey, z: Scalar, sign: Signature) -> bool {
        let (r, s) = (sign.x, sign.y);
        let u1 = s.mul_inverse() * z;
        let u2 = s.mul_inverse() * r;
        let p = u1 * self.g + u2 * pk;
        r == p.x % self.p
    }

    pub fn dh(self_sk: SecretKey, other_pk: PublicKey) -> Scalar {
        let session = self_sk * other_pk;
        session.x
    }
}
