pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// Two-input Poseidon preimage: proves knowledge of (in[0], in[1]) whose
// Poseidon digest is `out`.
//
// The target curve is a compile-time `--prime` flag; the source is
// curve-independent. The exact constraint and wire counts are not
// portable across compiler and template-library versions — Poseidon's
// round constants are field-specific — so the reader/satisfaction tests
// assert PROPERTIES (parse succeeds, witness satisfies), not a frozen
// shape.
template Poseidon2() {
    signal input in[2];
    signal output out;

    component hash = Poseidon(2);
    hash.inputs[0] <== in[0];
    hash.inputs[1] <== in[1];

    out <== hash.out;
}

component main = Poseidon2();
