pragma circom 2.0.0;

// Minimal multiplication circuit: proves knowledge of (a, b) with a * b = c.
//
// The target curve is selected at COMPILE time via circom's `--prime` flag
// (`bls12381` or the default `bn128` = BN254), not in this source — the .circom
// is curve-independent, so one file serves both curve targets. See REGENERATE.md.
//
// circom compiles this to a SINGLE rank-1 constraint. Spartan requires a
// power-of-two row count, so the Spartan-side reader tests use a hand-crafted,
// padding-augmented multiplier2 (two constraints) defined in
// `CircomR1csFixtures.cs`, not this circom output. This source documents the
// canonical un-padded circuit and is what a regenerated multiplier2 `.r1cs`
// would contain.
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main = Multiplier2();
