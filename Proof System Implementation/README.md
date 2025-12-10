# Proof System Implementation
The *ZeroMT* "multi-transfer zero-knowledge proof system" is a combination of multiple proof systems. This implementation aims to provide a library that exposes each proof system in non-interactive form as a separate, modular unit. This allows users to integrate either the complete *ZeroMT* proof system or any of its sub-proof systems into their applications. Furthermore, the modular design enables the evaluation of the performance of each implemented proof in terms of execution time and memory usage.

The implementation is written in **Rust**, as it provides a fast way to prototype memory-efficient programs while offering a wide variety of third-party packages, called *crates*, through the Cargo package manager and the community's crate registry *crates.io*.

This codebase contains both the logic of the *ZeroMT* proof system and its underlying proof systems, including *Bulletproofs* and four $\Sigma$-protocols. It also provides a test suite to ensure correctness and benchmarking modules for performance evaluation.

## External crates
### `merlin`

[`merlin`](https://github.com/zkcrypto/merlin) is a library that provides a Fiat-Shamir heuristic using a STROBE-based transcript, allowing non-interactive proof systems to be written by specifying the interactive (public-coin) protocol.

By using `merlin` for both the prover and the verifier in a proof system, the interaction reduces to a single proof message sent from the prover to the verifier. Prior to this proof exchange, both the prover and the verifier interact with a transcript that handles all the communication that would occur between the two parties. Whenever, by protocol definition, the prover sends a scalar or an elliptic-curve point to the verifier, this message is instead absorbed into the transcript, which updates its internal state with the new values. When the protocol would normally require the verifier to forward a randomly-sampled challenge to the prover, this step is replaced by the transcript instead: the prover queries the transcript, which generates a challenge derived from its current state. Once the prover reaches the end of the protocol, a proof is constructed from all the values the prover has committed to the transcript. Given this proof, the verifier synchronizes its own transcript by feeding it the same elements in the same order as the prover.

By maintaining a pair of transcripts that are consistent for both the prover and the verifier, `merlin` ensures the correctness of the implemented protocol, i.e., that all derived elements take the same values on both sides.
A peculiar feature of the `merlin` transcripts is that they can be reused across multiple proof systems, as long as they are in the same order on both prover and verifier side.

### `arkworks` ecosystem

Crucial to the implementation of a proof system is a library that provides arithmetic over elliptic curve points and finite field elements, i.e., the objects that are manipulated during the protocols. In this work, all such needs are fulfilled by the [`arkworks`](https://github.com/arkworks-rs) Rust ecosystem.

Moreover, the `arkworks` libraries are used to handle serialization and deserialization of elliptic curves points and finite field elements, both within the `merlin` transcript logic and the benchmarking codebase.

## Elliptic curve of choice

For all group operations on elements of $\mathbb{G}$, the ZeroMT proof systems uses the Barreto–Naehrig curve **BN-254** as underlying elliptic curve. 

## Usage of the library

### *ZeroMT* full proof system
To prove that
- each of the currency amounts in $\mathbf{a}$ is positive 
  $$\forall a_i \in (a_1, \dots, a_{m-1}): a_i \in [0,MAX], \; MAX = 2^n - 1;$$
- sender remaining currency balance $b'$ after the transfer  is positive
  $$b' \in [0,MAX], \; MAX = 2^n - 1;$$
- a sender knows a secret private key $sk$ for which the respective public key $y$ encrypts the values in $\textbf{C}$ and the such public key is well-formed  
  $$y = sk \cdot g;$$
- a sender knows a randomness value $r$ to be used in the encryption process for which 
  $$D = r \cdot g;$$
- a sender balance cannot be overdraft, i.e. the sender remaining encrypted balance is equal to the subtraction between the current sender encrypted balance and all of the $(m-1)$ encrypted currency amounts contained in $\mathbf{C}$ 
  $$C_L - \sum_{i=1}^{m-1}C_i = b' \cdot g + sk \cdot (C_R- \sum_{i=1}^{m-1}D);$$
- the i-th values in both $\textbf{C}$ and $\bar{\textbf{C}}$ are well-formed and are the result of the encryption of the i-th currency amount to be transferred 
  
$$(C_{i} = a_{i} \cdot g + r \cdot y \wedge \bar{C}_{i} = a_{i} \cdot g + r \cdot \bar{y}_{i} \wedge D=r \cdot g)^{m-1}_{i=1}.$$

Prover $\mathcal{P}$ inputs:
- Random Number Generator in `rand::Rng`;
- A `merlin` transcript;
- $n$, dimension in bits of the range proof;
- $g \in \mathbb{G}$, random generator;
- $h \in \mathbb{G}$, random generator;
- $\mathbf{g} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $\mathbf{h} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $\mathbf{a} \in \mathbb{Z}_p^{m-1}$, cryptocurrency amounts to be transferred;
- $b' \in \mathbb{Z}_p$, sender remaining balance;
- $u \in \mathbb{G}$, random generator required for the inner-product argument;
- $r \in \mathbb{Z}_p$, randomness associated with the ElGamal encryption scheme;
- $D \in \mathbb{G}$, factor for ElGamal scheme;
- $C_R \in \mathbb{G}$, right side of the sender balance, encrypted by means of ElGamal encryption and sender public key;
- $sk \in \mathbb{Z}_p$, sender private key;
- $y \in \mathbb{G}$, sender public key;
- $\bar{\mathbf{y}} \in \mathbb{G}^{m-1}$, recipients' public keys.

Verifier $\mathcal{V}$ inputs:
- A `merlin` transcript;
- $n$, dimension in bits of the range proof;
- $g \in \mathbb{G}$, random generator;
- $h \in \mathbb{G}$, random generator;
- $\mathbf{g} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $\mathbf{h} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $u \in \mathbb{G}$, random generator required for the inner-product argument;
- $D \in \mathbb{G}$, factor for ElGamal scheme;
- $C_L \in \mathbb{G}$, left side of the sender balance, encrypted by means of ElGamal encryption and sender public key;
- $C_R \in \mathbb{G}$, right side of the sender balance, encrypted by means of ElGamal encryption and sender public key;
- $\mathbf{C} \in \mathbb{G}^{m-1}$, cryptocurrency amounts, encrypted by means of ElGamal encryption and sender public key;
- $\bar{\mathbf{C}} \in \mathbb{G}^{m-1}$, cryptocurrency amounts, encrypted by means of ElGamal encryption and recipients' public keys;
- $y \in \mathbb{G}$, sender public key;
- $\bar{\mathbf{y}} \in \mathbb{G}^{m-1}$, recipients' public keys.
```rust
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use merlin::Transcript;
use serial_test::serial;
use std::io::Error;
use zeromt::{ElGamal, Utils, ZeroMTProof, ZeroMTProver, ZeroMTVerifier};

// Random Number Generator
let mut rng = ark_std::rand::thread_rng();
// Number of cryptocurrency amounts to be transferred (increased by one)
let mut m: usize = 16;
// Dimension in bit of the range proof
let mut n: usize = 16;
// Prover transcript setup
let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Verifier transcript setup
let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Random generator g
let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Random generator h
let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Randomness r
let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
// Random generator u
let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Vector g of random generators
let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
// Vector h of random generators
let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
// Random values for sender balance and cryptocurrency amounts to be transferred
let (balance, amounts, remaining_balance) = Utils::get_mock_balances(m, n, &mut rng);
// Random sender private key
let sender_priv_key: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
// Random recipients private keys
let recipients_priv_keys: Vec<ScalarField> = Utils::get_n_random_scalars_not_zero(amounts.len(), &mut rng);
// Sender public key, generated by means of ElGamal encryption
let sender_pub_key: G1Point = ElGamal::elgamal_calculate_pub_key(&sender_priv_key, &g);
// Recipients' public keys, generated by means of ElGamal encryption
let recipients_pub_keys: Vec<G1Point> = recipients_priv_keys.iter().map(|key: &ScalarField| ElGamal::elgamal_calculate_pub_key(key, &g)).collect();
// Sender balance, encrypted by means of ElGamal encryption and sender public key
let (c_l, c_r): (G1Point, G1Point) = ElGamal::elgamal_encrypt(balance, &sender_pub_key, &g, &r);
// Factor D for ElGamal scheme
let d: G1Point = ElGamal::elgamal_d(&g, &r);
// Cryptocurrency amounts, encrypted by means of ElGamal encryption and sender public key
let c_vec: Vec<G1Point> = amounts.iter().map(|a: &usize| ElGamal::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0).collect();
// Cryptocurrency amounts, encrypted by means of ElGamal encryption and recipients' public keys
let c_bar_vec: Vec<G1Point> = amounts.iter().zip(recipients_pub_keys.iter()).map(|(a, k)| ElGamal::elgamal_encrypt(*a, k, &g, &r).0).collect();

// Proof generation
let proof: ZeroMTProof = ZeroMTProver::new(&g, &h, remaining_balance, &amounts, &g_vec, &h_vec, &u, n, &d, &c_r, &sender_priv_key, &r, &sender_pub_key, &recipients_pub_keys).generate_proof(&mut rng, &mut prover_trans);
// Proof verification
let verification_result: Result<(), Error> = ZeroMTVerifier::new(&g, &h, n, &g_vec, &h_vec, &u, &d, &c_r, &c_l, &c_vec, &c_bar_vec, &sender_pub_key, &recipients_pub_keys).verify_proof(&proof, &mut verifier_trans);
```

### *Bulletproofs* aggregated range proof and inner-product argument
To prove that
- each of the currency amounts in $\mathbf{a}$ is positive
    $$\forall a_i \in (a_1, \dots, a_{m-1}): a_i \in [0,MAX], \; MAX = 2^n - 1;$$
- sender remaining currency balance $b'$ after the transfer  is positive
    $$b' \in [0,MAX], \; MAX = 2^n - 1.$$

Prover $\mathcal{P}$ inputs:
- Random Number Generator in `rand::Rng`;
- A `merlin` transcript;
- $n$, dimension in bits of the range proof;
- $g \in \mathbb{G}$, random generator;
- $h \in \mathbb{G}$, random generator;
- $\mathbf{g} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $\mathbf{h} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $\mathbf{a} \in \mathbb{Z}_p^{m-1}$, cryptocurrency amounts to be transferred;
- $b' \in \mathbb{Z}_p$, sender remaining balance;
- $u \in \mathbb{G}$, random generator required for the inner-product argument;
- $\mathbf{l} \in \mathbb{Z}_p^{m \cdot n}$, former element involved in the inner product to be verified. Obtained from the range proof; 
- $\mathbf{r} \in \mathbb{Z}_p^{m \cdot n}$, latter element involved in the inner product to be verified. Obtained from the range proof;
- $c \in \mathbb{Z}_p$, inner product to verify. Obtained from the range proof as $\hat{t} = \langle \mathbf{l}, \mathbf{r} \rangle$;
- $P \in \mathbb{G}$, commitment to elements involved in an inner product. Obtained from the range proof as $P - \mu \cdot h$.

Verifier $\mathcal{V}$ inputs:
- A `merlin` transcript;
- $n$, dimension in bits of the range proof;
- $m$, number of cryptocurrency amounts to be transferred (increased by one);
- $g \in \mathbb{G}$, random generator;
- $h \in \mathbb{G}$, random generator;
- $\mathbf{g} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $\mathbf{h} \in \mathbb{G}^{m \cdot n}$, vector of random generators;
- $u \in \mathbb{G}$, random generator required for the inner-product argument;
- $c \in \mathbb{Z}_p$, inner product to verify. Obtained from the range proof as $\hat{t} = \langle \mathbf{l}, \mathbf{r} \rangle$;
- $P \in \mathbb{G}$, commitment to elements involved in an inner product. Obtained from the range proof as $P - \mu \cdot h$.
```rust
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use merlin::Transcript;
use serial_test::serial;
use std::io::Error;
use zeromt::{ InnerProof, InnerProver, InnerVerifier, RangeProof, RangeProver, RangeVerifier, Utils};

// Random Number Generator
let mut rng = ark_std::rand::thread_rng();
// Number of cryptocurrency amounts to be transferred (increased by one)
let mut m: usize = 16;
// Dimension in bit of the range proof
let mut n: usize = 16;
// Prover transcript setup
let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Verifier transcript setup
let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Random generator g
let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Random generator h
let h: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Vector g of random generators
let g_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
// Vector h of random generators
let h_vec: Vec<G1Point> = Utils::get_n_generators(m * n, &mut rng);
// Random values for sender balance and cryptocurrency amounts to be transferred
let (_balance_start, amounts, remaining_balance) = Utils::get_mock_balances(m, n, &mut rng);

let mut range_prover: RangeProver = RangeProver::new(&g, &h, balance_remaining, &amounts, &g_vec, &h_vec, n);

let mut range_verifier: RangeVerifier = RangeVerifier::new(&g, &h, m, n);
// Range proof generation
let (range_proof, l_poly_vec, r_poly_vec, x_prover, y_prover, z_prover): (RangeProof, Vec<ScalarField>, Vec<ScalarField>, ScalarField, ScalarField, ScalarField) = range_prover.generate_proof(&mut rng, &mut prover_trans);
// Range proof verification
let (range_proof_result, x_verifier, y_verifier, _z_verifier): (Result<(), Error>, ScalarField, ScalarField, ScalarField) = range_verifier.verify_proof(&range_proof, &mut verifier_trans);

// Random generator u
let u: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Inner-product argument prover setup
let (h_first_vec_prover, phu_prover): (Vec<G1Point>, G1Point) = range_prover.get_ipa_arguments(&x_prover, &y_prover, &z_prover, range_proof.get_mu(), range_proof.get_a(), range_proof.get_s(), &h, &g_vec, &h_vec);
// Inner-product argument verifier setup
let (h_first_vec_verifier, phu_verifier): (Vec<G1Point>, G1Point) = range_verifier.get_ipa_arguments(&x_verifier, &y_verifier, &z_prover, range_proof.get_mu(), range_proof.get_a(), range_proof.get_s(), &h, &g_vec, &h_vec);


// Inner-product argument proof generation
 let inner_proof: InnerProof = InnerProver::new(&g_vec, &h_first_vec_prover, &phu_prover, range_proof.get_t_hat(), &l_poly_vec, &r_poly_vec, &u) .generate_proof(&mut prover_trans);
// Inner-product argument proof verification
let inner_result: Result<(), Error> = InnerVerifier::new(&g_vec, &h_first_vec_verifier, &phu_verifier, range_proof.get_t_hat(), &u) .verify_proof_multiscalar(&inner_proof, &mut verifier_trans);
```
### $\Sigma$-protocol `sk`
To prove a sender knows a secret private key $sk$ for which the respective public key $y$ encrypts the values in $\textbf{C}$ and the such public key is well-formed 
$$y = sk \cdot g.$$

Prover $\mathcal{P}$ inputs:
- Random Number Generator in `rand::Rng`;
- A `merlin` transcript;
- $g \in \mathbb{G}$, random generator;
- $sk \in \mathbb{Z}_p$, sender private key.

Verifier $\mathcal{V}$ inputs:
- A `merlin` transcript;
- $g \in \mathbb{G}$, random generator;
- $y \in \mathbb{G}$, sender public key.

```rust
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use merlin::Transcript;
use std::io::Error;
use zeromt::{ElGamal, SigmaSKProof, SigmaSKProver, SigmaSKVerifier, Utils};

// Random Number Generator
let mut rng = ark_std::rand::thread_rng();
// Number of cryptocurrency amounts to be transferred (increased by one)
let mut m: usize = 16;
// Dimension in bit of the range proof
let mut n: usize = 16;
// Prover transcript setup
let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Verifier transcript setup
let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");

// Random generator g
let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Random sender private key
let sk: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
// Sender public key, generated by means of ElGamal encryption
let y: G1Point = ElGamal::elgamal_calculate_pub_key(&sk, &g);

// Proof generation
let proof: SigmaSKProof = SigmaSKProver::new(&g, &sk).generate_proof(&mut rng, &mut prover_trans);
// Proof verification
let result: Result<(), Error> = SigmaSKVerifier::new(&g, &y).verify_proof(&proof, &mut verifier_trans);
                    
```
### $\Sigma$-protocol `r`
To prove a sender knows a randomness value $r$ to be used in the encryption process for which 
$$D = r \cdot g.$$

Prover $\mathcal{P}$ inputs:
- Random Number Generator in `rand::Rng`;
- A `merlin` transcript;
- $g \in \mathbb{G}$, random generator;
- $r \in \mathbb{Z}_p$, randomness associated with the ElGamal encryption scheme.

Verifier $\mathcal{V}$ inputs:
- A `merlin` transcript;
- $g \in \mathbb{G}$, random generator;
- $D \in \mathbb{G}$, factor for ElGamal scheme.
```rust
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use merlin::Transcript;
use std::io::Error;
use zeromt::{ElGamal, SigmaRProof, SigmaRProver, SigmaRVerifier, Utils};

// Random Number Generator
let mut rng = ark_std::rand::thread_rng();
// Number of cryptocurrency amounts to be transferred (increased by one)
let mut m: usize = 16;
// Dimension in bit of the range proof
let mut n: usize = 16;
// Prover transcript setup
let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Verifier transcript setup
let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");

// Random generator g
let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Randomness r
let r: ScalarField = Utils::get_n_random_scalars(1, &mut rng)[0];
// Factor D for ElGamal scheme
let d: G1Point = ElGamal::elgamal_d(&g, &r);

// Proof generation
let proof: SigmaRProof = SigmaRProver::new(&g, &r).generate_proof(&mut rng, &mut prover_trans);
// Proof verification
let result: Result<(), Error> = SigmaRVerifier::new(&g, &d).verify_proof(&proof, &mut verifier_trans);
```
### $\Sigma$-protocol `ab`

To prove a sender balance cannot be overdraft, i.e. the sender remaining encrypted balance is equal to the subtraction between the current sender encrypted balance and all of the $(m-1)$ encrypted currency amounts contained in $\mathbf{C}$ 
$$C_L - \sum_{i=1}^{m-1}C_i = b' \cdot g + sk \cdot (C_R- \sum_{i=1}^{m-1}D).$$

Prover $\mathcal{P}$ inputs:
- Random Number Generator in `rand::Rng`;
- A `merlin` transcript;
- $g \in \mathbb{G}$, random generator;
- $D \in \mathbb{G}$, factor for ElGamal scheme;
- $C_R \in \mathbb{G}$, right side of the sender balance, encrypted by means of ElGamal encryption and sender public key;
- $sk \in \mathbb{Z}_p$, sender private key;
- $\mathbf{a} \in \mathbb{Z}_p^{m-1}$, cryptocurrency amounts to be transferred;
- $b' \in \mathbb{Z}_p$, sender remaining balance.

Verifier $\mathcal{V}$ inputs:
- A `merlin` transcript;
- $g \in \mathbb{G}$, random generator;
- $D \in \mathbb{G}$, factor for ElGamal scheme;
- $C_L \in \mathbb{G}$, left side of the sender balance, encrypted by means of ElGamal encryption and sender public key;
- $C_R \in \mathbb{G}$, right side of the sender balance, encrypted by means of ElGamal encryption and sender public key;
- $\mathbf{C} \in \mathbb{G}^{m-1}$, cryptocurrency amounts, encrypted by means of ElGamal encryption and sender public key.

```rust
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use merlin::Transcript;
use std::io::Error;
use zeromt::{ElGamal, SigmaABProof, SigmaABProver, SigmaABVerifier, Utils};

// Random Number Generator
let mut rng = ark_std::rand::thread_rng();
// Number of cryptocurrency amounts to be transferred (increased by one)
let mut m: usize = 16;
// Dimension in bit of the range proof
let mut n: usize = 16;
// Prover transcript setup
let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Verifier transcript setup
let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Random generator g
let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Randomness r
let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
// Random values for sender balance and cryptocurrency amounts to be transferred
let (balance, amounts, remaining_balance) = Utils::get_mock_balances(m, n, &mut rng);
// Random sender private key   
let sender_priv_key: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
// Sender public key, generated by means of ElGamal encryption
let sender_pub_key: G1Point = ElGamal::elgamal_calculate_pub_key(&sender_priv_key, &g);
// Sender balance, encrypted by means of ElGamal encryption and sender public key
let (c_l, c_r): (G1Point, G1Point) = ElGamal::elgamal_encrypt(balance, &sender_pub_key, &g, &r);
// Factor D for ElGamal scheme
let d: G1Point = ElGamal::elgamal_d(&g, &r);
// Cryptocurrency amounts, encrypted by means of ElGamal encryption and sender public key
let c_vec: Vec<G1Point> = amounts.iter().map(|a:&usize| ElGamal::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0).collect();

// Proof generation
let proof: SigmaABProof = SigmaABProver::new(&g, &d, &c_r, remaining_balance, &amounts, &sender_priv_key).generate_proof(&mut rng, &mut prover_trans);
// Proof verification
let result: Result<(), Error> = SigmaABVerifier::new(&g, &d, &c_r, &c_l, &c_vec).verify_proof(&proof, &mut verifier_trans);

```
### $\Sigma$-protocol `y`
To prove the i-th values in both $\textbf{C}$ and $\bar{\textbf{C}}$ are well-formed and are the result of the encryption of the i-th currency amount to be transferred 

$$(C_{i} = a_{i} \cdot g + r \cdot y \wedge \bar{C}_{i} = a_{i} \cdot g + r \cdot \bar{y}_{i} \wedge D=r \cdot g)^{m-1}_{i=1}.$$

Prover $\mathcal{P}$ inputs:
- Random Number Generator in `rand::Rng`;
- A `merlin` transcript;
- $y \in \mathbb{G}$, sender public key;
- $\bar{\mathbf{y}} \in \mathbb{G}^{m-1}$, recipients' public keys
- $r \in \mathbb{Z}_p$, randomness associated with the ElGamal encryption scheme.

Verifier $\mathcal{V}$ inputs:
- A `merlin` transcript;
- $y \in \mathbb{G}$, sender public key;
- $\bar{\mathbf{y}} \in \mathbb{G}^{m-1}$, recipients' public keys;
- $\mathbf{C} \in \mathbb{G}^{m-1}$, cryptocurrency amounts, encrypted by means of ElGamal encryption and sender public key;
- $\bar{\mathbf{C}} \in \mathbb{G}^{m-1}$, cryptocurrency amounts, encrypted by means of ElGamal encryption and recipients' public keys.


```rust
use ark_bn254::{Fr as ScalarField, G1Affine as G1Point};
use merlin::Transcript;
use std::io::Error;
use zeromt::{ElGamal, SigmaYProof, SigmaYProver, SigmaYVerifier, Utils};

// Random Number Generator
let mut rng = ark_std::rand::thread_rng();
// Number of cryptocurrency amounts to be transferred (increased by one)
let mut m: usize = 16;
// Dimension in bit of the range proof
let mut n: usize = 16;
// Prover transcript setup
let mut prover_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Verifier transcript setup
let mut verifier_trans: Transcript = Transcript::new(b"ZeroMTTest");
// Random generator g
let g: G1Point = Utils::get_n_generators(1, &mut rng)[0];
// Randomness r
let r: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
// Random values for sender balance and cryptocurrency amounts to be transferred
let (_balance_start, amounts, _remaining_balance) = Utils::get_mock_balances(m, n, &mut rng);
// Random sender private key
let sender_priv_key: ScalarField = Utils::get_n_random_scalars_not_zero(1, &mut rng)[0];
// Random recipients private keys
let recipients_priv_keys: Vec<ScalarField> = Utils::get_n_random_scalars_not_zero(amounts.len(), &mut rng);
// Sender public key, generated by means of ElGamal encryption
let sender_pub_key: G1Point = ElGamal::elgamal_calculate_pub_key(&sender_priv_key, &g);
// Recipients' public keys, generated by means of ElGamal encryption
let recipients_pub_keys: Vec<G1Point> = recipients_priv_keys.iter().map(|key: &ScalarField| ElGamal::elgamal_calculate_pub_key(key, &g)).collect();
// Cryptocurrency amounts, encrypted by means of ElGamal encryption and sender public key
let c_vec: Vec<G1Point> = amounts.iter().map(|a: &usize| ElGamal::elgamal_encrypt(*a, &sender_pub_key, &g, &r).0).collect();
// Cryptocurrency amounts, encrypted by means of ElGamal encryption and recipients' public keys
let c_bar_vec: Vec<G1Point> = amounts.iter().zip(recipients_pub_keys.iter()).map(|(a, k)| ElGamal::elgamal_encrypt(*a, k, &g, &r).0).collect();

// Proof generation
let proof: SigmaYProof = SigmaYProver::new(&r, &sender_pub_key, &recipients_pub_keys).generate_proof(&mut rng, &mut prover_trans); 
// Proof verification
let result: Result<(), Error> = SigmaYVerifier::new(&sender_pub_key, &recipients_pub_keys, &c_vec, &c_bar_vec).verify_proof(&proof, &mut verifier_trans);
```
