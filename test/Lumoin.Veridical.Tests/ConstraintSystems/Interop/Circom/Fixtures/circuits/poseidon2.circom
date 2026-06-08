pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// Two-input Poseidon preimage: proves knowledge of (in[0], in[1]) whose
// Poseidon digest is `out`. Mirrors the shape of the previously-imported
// poseidon fixture (a circomlib Poseidon(2) two-input preimage).
//
// The target curve is a compile-time `--prime` flag (see REGENERATE.md); the
// source is curve-independent. The exact constraint and wire counts are
// circomlib-VERSION-dependent — Poseidon's round constants are field-specific
// and emitted by circom per `--prime` — so REGENERATE.md pins the circomlib
// version. A regeneration with a different circomlib version may produce a
// different constraint count than the historically-imported fixture's 100; the
// reader/satisfaction tests assert PROPERTIES (parse succeeds, witness
// satisfies), not a frozen shape.
template Poseidon2() {
    signal input in[2];
    signal output out;

    component hash = Poseidon(2);
    hash.inputs[0] <== in[0];
    hash.inputs[1] <== in[1];

    out <== hash.out;
}

component main = Poseidon2();
