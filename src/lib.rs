#![deny(unused_import_braces, unused_qualifications, trivial_casts)]
#![deny(trivial_numeric_casts, variant_size_differences)]
#![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
#![deny(unused_attributes, unused_mut)]
//#![deny(missing_docs)]
//#![deny(unused_imports)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use)]
#![forbid(unsafe_code)]

/// Crypto primitives: ElGamal encryption, PRFs
pub mod crypto;

/// Aggregation-only encryption scheme
pub mod agg_only_enc;

///// Proofs for protecting against malicious clients
//pub mod provers;

// TODO: End-to-end code is out of date
//
//pub mod net;
