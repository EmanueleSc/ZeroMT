fn main() {
    println!("Hello, Proof System!");
}

// OLD STAFF
/*
Schnorr Sigma-protocol for DL relation:

Public inputs: G (group generator) and H = w * G
Private inputs: w (scalar value)

Prover:
    rand 'r' from group
    computes A = r * G
    sends 'A' to the verifier

Verifier:
    rand challange 'e' from group 
    sends 'e' to the prover

Prover:
    computes z = (we + r) mod |group|
    sends 'z' to the verifier

Verifier:
    cheks if A + (e * H) = z * G

TRANSCRIPT = (A, e, z)
*/
/*
let mut rng = rand::thread_rng();

// Prover inputs 
let G = G1::new(G1_GENERATOR_X, G1_GENERATOR_Y, false);
let w = ScalarField::from(42u64);
let H = G.mul(w.into_repr()).into_affine();

println!("------ PROVER INPUTS ------");
println!("Generator G: {:?} - on curve: {}", G, G.is_on_curve());
println!("Witness w: {:?}", w);
println!("Group elem H: {:?} - on curve: {}", H, H.is_on_curve());

// Prover computes:
let r = ScalarField::rand(&mut rng);
let A = G.mul(r.into_repr()).into_affine();

println!("-> PROVER computes:");
println!("r {:?}", r);
println!("Group elem A {:?} - on curve {}", A, A.is_on_curve());

// Verifier computes:
let e = ScalarField::rand(&mut rng);

println!("-> VERIFIER challange:");
println!("e {:?}", e);

// Prover computes:
let z = (w * e) + r;

println!("-> PROVER computes:");
println!("z {:?}", z);

// Verifier checks:
let left_eq = (H.mul(e.into_repr()).into_affine()) + A;
let right_eq = G.mul(z.into_repr()).into_affine();

println!("-> VERIFIER checks:");
println!("left_eq: {:?} - on curve: {}", left_eq, left_eq.is_on_curve());
println!("right_eq: {:?} - on curve: {}", right_eq, right_eq.is_on_curve());

assert_eq!(left_eq, right_eq);
*/

