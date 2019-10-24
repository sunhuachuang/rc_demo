mod curve;

use curve::{Curve, Scalar};

fn main() {
    let curve = Curve::new();
    let (sk, pk) = curve.generate_keypair();
    println!("generate sk: {:?}, pk: {:?}", sk, pk);

    let message: Scalar = Scalar(123456);
    let signature = curve.sign(sk, message);
    println!("sign: {:?}", signature);
    println!("verify: {:?}", curve.verify(pk, message, signature));

    let (sk2, pk2) = curve.generate_keypair();

    println!(
        "DH: {:?}, Result: {:?}",
        Curve::dh(sk, pk2),
        Curve::dh(sk, pk2) == Curve::dh(sk2, pk)
    );
}
