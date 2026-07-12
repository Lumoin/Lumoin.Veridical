using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Telemetry;

/// <summary>
/// Identifies a kind of cryptographic operation for counting and event
/// streaming via <see cref="CryptographicOperationCounters"/>.
/// </summary>
/// <remarks>
/// <para>
/// Modelled on <see cref="CurveParameterSet"/> and
/// <see cref="AlgebraicRole"/>: a small <c>readonly struct</c> with a
/// numeric <see cref="Code"/>, named static values for the kinds the
/// library knows about, and a <see cref="Create"/> factory so applications
/// can register kinds the library does not know about — a custom proof
/// system's bespoke operation, a project-specific tally, and so on.
/// </para>
/// <para>
/// Codes are partitioned by surface so future batches can extend any
/// category without renumbering: 1–9 are the scalar-field operations,
/// 10–19 the base-field operations (when introduced), 20–39 the G1 group
/// operations, 40–59 G2 / GT, 60–79 polynomial and FFT operations, and
/// codes above 1000 are reserved for application extensions.
/// </para>
/// </remarks>
[DebuggerDisplay("{CryptographicOperationKindNames.GetName(this),nq}")]
public readonly struct CryptographicOperationKind: IEquatable<CryptographicOperationKind>
{
    /// <summary>Gets the numeric code for this operation kind.</summary>
    public int Code { get; }


    private CryptographicOperationKind(int code) { Code = code; }


    /// <summary>The sentinel "no operation". Reserved as code zero; not emitted by any backend.</summary>
    public static CryptographicOperationKind None { get; } = new(0);


    //Scalar-field operations: 1-9.

    /// <summary>Addition in the scalar field.</summary>
    public static CryptographicOperationKind ScalarAdd { get; } = new(1);

    /// <summary>Subtraction in the scalar field.</summary>
    public static CryptographicOperationKind ScalarSubtract { get; } = new(2);

    /// <summary>Multiplication in the scalar field.</summary>
    public static CryptographicOperationKind ScalarMultiply { get; } = new(3);

    /// <summary>Additive negation in the scalar field.</summary>
    public static CryptographicOperationKind ScalarNegate { get; } = new(4);

    /// <summary>Multiplicative inverse in the scalar field.</summary>
    public static CryptographicOperationKind ScalarInvert { get; } = new(5);

    /// <summary>Modular reduction into the scalar field's canonical range.</summary>
    public static CryptographicOperationKind ScalarReduce { get; } = new(6);

    /// <summary>Uniform random sampling from the scalar field.</summary>
    public static CryptographicOperationKind ScalarRandom { get; } = new(7);

    /// <summary>Batched scalar-field addition. A single batched call of count N increments by N.</summary>
    public static CryptographicOperationKind ScalarBatchAdd { get; } = new(8);

    /// <summary>Batched scalar-field subtraction. A single batched call of count N increments by N.</summary>
    public static CryptographicOperationKind ScalarBatchSubtract { get; } = new(9);

    /// <summary>Hash bytes to a scalar via RFC 9380 <c>expand_message_xmd</c> + modular reduction.</summary>
    public static CryptographicOperationKind HashToScalar { get; } = new(10);

    /// <summary>Batched scalar-field multiplication. A single batched call of count N increments by N.</summary>
    public static CryptographicOperationKind ScalarBatchMultiply { get; } = new(11);

    /// <summary>
    /// Batched fused multiply-accumulate in the scalar field — the dot-product-shaped
    /// <c>acc[i] += a[i]·b[i]</c> primitive, including its broadcast-scalar and
    /// gather/scatter variants and the LCH14 butterfly batch. A single batched call of
    /// count N increments by N (counting the multiplies, not the fused adds), mirroring
    /// how <see cref="ScalarBatchMultiply"/> counts its batch.
    /// </summary>
    public static CryptographicOperationKind ScalarBatchMultiplyAccumulate { get; } = new(12);


    //Fp2 extension-field operations: 40-49.
    //(The 10-19 range is reserved for base-field Fp ops; Fp2 is the smallest
    //extension field and lives in the pairing-side 40-59 block alongside
    //future G2 / GT / pairing entries.)

    /// <summary>Addition in the BLS12-381 Fp2 extension field.</summary>
    public static CryptographicOperationKind Fp2Add { get; } = new(40);

    /// <summary>Subtraction in the BLS12-381 Fp2 extension field.</summary>
    public static CryptographicOperationKind Fp2Subtract { get; } = new(41);

    /// <summary>Multiplication in the BLS12-381 Fp2 extension field.</summary>
    public static CryptographicOperationKind Fp2Multiply { get; } = new(42);

    /// <summary>Squaring in the BLS12-381 Fp2 extension field.</summary>
    public static CryptographicOperationKind Fp2Square { get; } = new(43);

    /// <summary>Additive negation in the BLS12-381 Fp2 extension field.</summary>
    public static CryptographicOperationKind Fp2Negate { get; } = new(44);

    /// <summary>Multiplicative inverse in the BLS12-381 Fp2 extension field.</summary>
    public static CryptographicOperationKind Fp2Invert { get; } = new(45);

    /// <summary>Conjugation (Frobenius x^p) in the BLS12-381 Fp2 extension field.</summary>
    public static CryptographicOperationKind Fp2Conjugate { get; } = new(46);


    //G2 group operations: 50-57.

    /// <summary>Point addition in G2.</summary>
    public static CryptographicOperationKind G2Add { get; } = new(50);

    /// <summary>Point negation in G2.</summary>
    public static CryptographicOperationKind G2Negate { get; } = new(51);

    /// <summary>Scalar multiplication of a G2 point.</summary>
    public static CryptographicOperationKind G2ScalarMultiply { get; } = new(52);

    /// <summary>Hash-to-curve into G2 (RFC 9380 §8.8.2 including subgroup clearing).</summary>
    public static CryptographicOperationKind G2HashToCurve { get; } = new(53);

    /// <summary>On-curve membership validation for a G2 candidate.</summary>
    public static CryptographicOperationKind G2IsOnCurve { get; } = new(54);

    /// <summary>Prime-order subgroup membership validation for a G2 candidate.</summary>
    public static CryptographicOperationKind G2IsInPrimeOrderSubgroup { get; } = new(55);


    //G1 group operations: 20-29.

    /// <summary>Point addition in G1.</summary>
    public static CryptographicOperationKind G1Add { get; } = new(20);

    /// <summary>Point negation in G1.</summary>
    public static CryptographicOperationKind G1Negate { get; } = new(21);

    /// <summary>Scalar multiplication of a G1 point.</summary>
    public static CryptographicOperationKind G1ScalarMultiply { get; } = new(22);

    /// <summary>Multi-scalar multiplication in G1.</summary>
    public static CryptographicOperationKind G1MultiScalarMultiply { get; } = new(23);

    /// <summary>Hash-to-curve into G1 (RFC 9380 §3 including subgroup clearing).</summary>
    public static CryptographicOperationKind G1HashToCurve { get; } = new(24);

    /// <summary>On-curve membership validation for a G1 candidate.</summary>
    public static CryptographicOperationKind G1IsOnCurve { get; } = new(25);

    /// <summary>Prime-order subgroup membership validation for a G1 candidate.</summary>
    public static CryptographicOperationKind G1IsInPrimeOrderSubgroup { get; } = new(26);


    //Polynomial and multilinear-extension operations: 60-79 per the
    //CryptographicOperationKind partitioning convention.

    /// <summary>Univariate polynomial evaluation at a point.</summary>
    public static CryptographicOperationKind PolynomialEvaluate { get; } = new(60);

    /// <summary>Coefficient-wise univariate polynomial addition.</summary>
    public static CryptographicOperationKind PolynomialAdd { get; } = new(61);

    /// <summary>Schoolbook univariate polynomial multiplication.</summary>
    public static CryptographicOperationKind PolynomialMultiply { get; } = new(62);

    /// <summary>Multilinear-extension folding of one variable against a challenge scalar.</summary>
    public static CryptographicOperationKind MleFold { get; } = new(63);

    /// <summary>Multilinear-extension evaluation at a point (n-element vector).</summary>
    public static CryptographicOperationKind MleEvaluate { get; } = new(64);


    //Fiat-Shamir transcript operations: 80-89.

    /// <summary>Initialisation of a Fiat-Shamir transcript (initial state derivation).</summary>
    public static CryptographicOperationKind TranscriptInitialise { get; } = new(80);

    /// <summary>Absorption of arbitrary bytes into a Fiat-Shamir transcript.</summary>
    public static CryptographicOperationKind TranscriptAbsorbBytes { get; } = new(81);

    /// <summary>Squeeze of a challenge from a Fiat-Shamir transcript (XOF call).</summary>
    public static CryptographicOperationKind TranscriptSqueezeBytes { get; } = new(82);

    /// <summary>State-update transition that follows every squeeze on a Fiat-Shamir transcript.</summary>
    public static CryptographicOperationKind TranscriptUpdateState { get; } = new(83);


    //Commitment-scheme operations: 100-119.

    /// <summary>Pedersen vector-commitment computation.</summary>
    public static CryptographicOperationKind PedersenCommit { get; } = new(100);

    /// <summary>Hyrax commit to a multilinear extension.</summary>
    public static CryptographicOperationKind HyraxCommit { get; } = new(101);

    /// <summary>Hyrax opening-proof generation.</summary>
    public static CryptographicOperationKind HyraxOpen { get; } = new(102);

    /// <summary>Hyrax opening-proof verification.</summary>
    public static CryptographicOperationKind HyraxVerify { get; } = new(103);

    /// <summary>Inner-product-argument proof generation.</summary>
    public static CryptographicOperationKind IpaProve { get; } = new(104);

    /// <summary>Inner-product-argument verification.</summary>
    public static CryptographicOperationKind IpaVerify { get; } = new(105);


    //Constraint-system operations: 120-139.

    /// <summary>Construction of an R1CS sparse-COO matrix.</summary>
    public static CryptographicOperationKind R1csConstructMatrix { get; } = new(120);

    /// <summary>Sparse matrix-vector product over the scalar field.</summary>
    public static CryptographicOperationKind R1csMatrixVectorProduct { get; } = new(121);

    /// <summary>R1CS satisfaction check (standard form).</summary>
    public static CryptographicOperationKind R1csCheckSatisfaction { get; } = new(122);

    /// <summary>Relaxed R1CS satisfaction check.</summary>
    public static CryptographicOperationKind RelaxedR1csCheckSatisfaction { get; } = new(123);

    /// <summary>One Nova-style relaxed-R1CS fold step (cross-term, challenge, and homomorphic combination together count as one increment).</summary>
    public static CryptographicOperationKind RelaxedR1csFold { get; } = new(124);


    //Sumcheck and Spartan-specific operations: 140-159.

    /// <summary>One round of the sumcheck protocol — round-polynomial computation, transcript absorb, and challenge squeeze together count as one increment.</summary>
    public static CryptographicOperationKind SumcheckRound { get; } = new(140);

    /// <summary>Evaluation of a sparse R1CS matrix viewed as a multilinear extension at a challenge point or row slice.</summary>
    public static CryptographicOperationKind SparseMatrixMleEvaluate { get; } = new(141);

    /// <summary>Construction of a Spartan verifier (wraps a verifying key).</summary>
    public static CryptographicOperationKind SpartanVerifierConstruct { get; } = new(142);

    /// <summary>Top-level Spartan verifier verification call.</summary>
    public static CryptographicOperationKind SpartanVerifierVerify { get; } = new(143);

    /// <summary>One round of sumcheck verification (transcript replay + decompress + evaluate at challenge).</summary>
    public static CryptographicOperationKind SumcheckRoundVerify { get; } = new(144);

    /// <summary>Computation of the public-and-one MLE evaluation at a challenge point.</summary>
    public static CryptographicOperationKind EvalPublicAndOneCompute { get; } = new(145);


    //Fp6 extension-field operations: 200-209.
    //(Fp6 = Fp2[v]/(v³ − (1+u)) is the cubic-over-quadratic layer in the
    //BLS12-381 tower. It has no consumer outside Fp12, but is surfaced as
    //its own delegate set for testability and so a GPU backend can fuse
    //Fp6 ops without flattening into Fp12 first.)

    /// <summary>Addition in the BLS12-381 Fp6 extension field.</summary>
    public static CryptographicOperationKind Fp6Add { get; } = new(200);

    /// <summary>Subtraction in the BLS12-381 Fp6 extension field.</summary>
    public static CryptographicOperationKind Fp6Subtract { get; } = new(201);

    /// <summary>Multiplication in the BLS12-381 Fp6 extension field.</summary>
    public static CryptographicOperationKind Fp6Multiply { get; } = new(202);

    /// <summary>Squaring in the BLS12-381 Fp6 extension field.</summary>
    public static CryptographicOperationKind Fp6Square { get; } = new(203);

    /// <summary>Additive negation in the BLS12-381 Fp6 extension field.</summary>
    public static CryptographicOperationKind Fp6Negate { get; } = new(204);

    /// <summary>Multiplicative inverse in the BLS12-381 Fp6 extension field.</summary>
    public static CryptographicOperationKind Fp6Invert { get; } = new(205);


    //Fp12 extension-field operations: 210-219.

    /// <summary>Addition in the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Add { get; } = new(210);

    /// <summary>Subtraction in the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Subtract { get; } = new(211);

    /// <summary>Multiplication in the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Multiply { get; } = new(212);

    /// <summary>Squaring in the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Square { get; } = new(213);

    /// <summary>Additive negation in the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Negate { get; } = new(214);

    /// <summary>Multiplicative inverse in the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Invert { get; } = new(215);

    /// <summary>Conjugation (the non-trivial Fp6-automorphism: w ↦ −w) in the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Conjugate { get; } = new(216);


    //Pairing-side Fp12 operations and the pairing itself: 220-229.

    /// <summary>Frobenius endomorphism (x ↦ x^p) on the BLS12-381 Fp12 extension field.</summary>
    public static CryptographicOperationKind Fp12Frobenius { get; } = new(220);

    /// <summary>Cyclotomic squaring on the BLS12-381 Fp12 extension field — valid only inside the cyclotomic subgroup, cheaper than the generic Fp12 square.</summary>
    public static CryptographicOperationKind Fp12CyclotomicSquare { get; } = new(221);

    /// <summary>Top-level pairing <c>e(P, Q) : G1 × G2 → GT ⊂ Fp12*</c>. Counts a single composed Miller loop + final exponentiation as one increment.</summary>
    public static CryptographicOperationKind Pairing { get; } = new(222);


    //BBS+ signature-scheme operations: 160-169.

    /// <summary>BBS+ key generation (derive secret-key scalar from input key material, compute public key on G2).</summary>
    public static CryptographicOperationKind BbsGenerate { get; } = new(160);

    /// <summary>BBS+ signing (produce a multi-message signature under a given header).</summary>
    public static CryptographicOperationKind BbsSign { get; } = new(161);

    /// <summary>BBS+ signature verification (check the pairing equation for a (signature, header, messages) triple under a public key).</summary>
    public static CryptographicOperationKind BbsVerify { get; } = new(162);

    /// <summary>BBS+ selective-disclosure proof generation (produce a zero-knowledge proof of knowledge of a signature, disclosing a chosen subset of messages).</summary>
    public static CryptographicOperationKind BbsGenerateProof { get; } = new(163);

    /// <summary>BBS+ selective-disclosure proof verification (check the proof against the disclosed messages and public key).</summary>
    public static CryptographicOperationKind BbsVerifyProof { get; } = new(164);


    //BBS blind-signature (draft-irtf-cfrg-bbs-blind-signatures-03) and
    //per-verifier-pseudonym (draft-irtf-cfrg-bbs-per-verifier-linkability-03)
    //extension operations: 165-175, immediately following the core BBS+
    //block (160-164) and before the next allocated block (Fp6, 200-209).

    /// <summary>Blind BBS commitment to a set of prover-chosen messages (<c>Commit</c>/<c>CoreCommit</c>), producing the Pedersen commitment plus its Schnorr proof of opening.</summary>
    public static CryptographicOperationKind BbsCommit { get; } = new(165);

    /// <summary>Blind BBS signing over a deserialized-and-validated commitment plus signer-known messages (<c>BlindSign</c>).</summary>
    public static CryptographicOperationKind BbsBlindSign { get; } = new(166);

    /// <summary>Blind BBS signature verification on the prover side, after unblinding (<c>VerifyBlindSign</c> / the core <c>Verify</c> called on the finalized signature).</summary>
    public static CryptographicOperationKind BbsBlindVerify { get; } = new(167);

    /// <summary>Blind BBS selective-disclosure proof generation, including committed-disclosure messages (<c>BlindProofGen</c>).</summary>
    public static CryptographicOperationKind BbsBlindGenerateProof { get; } = new(168);

    /// <summary>Blind BBS selective-disclosure proof verification (<c>BlindProofVerify</c>).</summary>
    public static CryptographicOperationKind BbsBlindVerifyProof { get; } = new(169);

    /// <summary>Per-verifier-pseudonym commitment to the prover's <c>nym_secrets</c> alongside any blind messages (<c>CommitWithNym</c>).</summary>
    public static CryptographicOperationKind BbsNymCommit { get; } = new(170);

    /// <summary>Per-verifier-pseudonym blind signing over a commitment carrying <c>nym_secrets</c> (<c>BlindSignWithNym</c>).</summary>
    public static CryptographicOperationKind BbsNymBlindSign { get; } = new(171);

    /// <summary>Per-verifier-pseudonym signature finalization/verification on the prover side (<c>VerifyFinalizeWithNym</c>).</summary>
    public static CryptographicOperationKind BbsNymVerifyFinalize { get; } = new(172);

    /// <summary>Per-verifier-pseudonym selective-disclosure proof generation, including the pseudonym computation (<c>ProofGenWithNym</c>).</summary>
    public static CryptographicOperationKind BbsNymGenerateProof { get; } = new(173);

    /// <summary>Per-verifier-pseudonym selective-disclosure proof verification (<c>ProofVerifyWithNym</c>).</summary>
    public static CryptographicOperationKind BbsNymVerifyProof { get; } = new(174);

    /// <summary>Blind BBS commitment verification on the signer side (the standalone <c>Verify</c> gate over a commitment-with-proof, mirroring <c>deserialize_and_validate_commit</c>).</summary>
    public static CryptographicOperationKind BbsCommitVerify { get; } = new(175);


    private static readonly List<CryptographicOperationKind> kinds =
    [
        None,
        ScalarAdd, ScalarSubtract, ScalarMultiply, ScalarNegate, ScalarInvert,
        ScalarReduce, ScalarRandom, ScalarBatchAdd, ScalarBatchSubtract, ScalarBatchMultiply, ScalarBatchMultiplyAccumulate,
        Fp2Add, Fp2Subtract, Fp2Multiply, Fp2Square, Fp2Negate, Fp2Invert, Fp2Conjugate,
        G2Add, G2Negate, G2ScalarMultiply, G2HashToCurve, G2IsOnCurve, G2IsInPrimeOrderSubgroup,
        G1Add, G1Negate, G1ScalarMultiply, G1MultiScalarMultiply,
        G1HashToCurve, G1IsOnCurve, G1IsInPrimeOrderSubgroup,
        PolynomialEvaluate, PolynomialAdd, PolynomialMultiply,
        MleFold, MleEvaluate,
        TranscriptInitialise, TranscriptAbsorbBytes, TranscriptSqueezeBytes, TranscriptUpdateState,
        PedersenCommit, HyraxCommit, HyraxOpen, HyraxVerify, IpaProve, IpaVerify,
        R1csConstructMatrix, R1csMatrixVectorProduct, R1csCheckSatisfaction, RelaxedR1csCheckSatisfaction, RelaxedR1csFold,
        SumcheckRound, SparseMatrixMleEvaluate,
        SpartanVerifierConstruct, SpartanVerifierVerify, SumcheckRoundVerify, EvalPublicAndOneCompute,
        Fp6Add, Fp6Subtract, Fp6Multiply, Fp6Square, Fp6Negate, Fp6Invert,
        Fp12Add, Fp12Subtract, Fp12Multiply, Fp12Square, Fp12Negate, Fp12Invert, Fp12Conjugate,
        Fp12Frobenius, Fp12CyclotomicSquare, Pairing,
        HashToScalar,
        BbsGenerate, BbsSign, BbsVerify, BbsGenerateProof, BbsVerifyProof,
        BbsCommit, BbsBlindSign, BbsBlindVerify, BbsBlindGenerateProof, BbsBlindVerifyProof,
        BbsNymCommit, BbsNymBlindSign, BbsNymVerifyFinalize, BbsNymGenerateProof, BbsNymVerifyProof,
        BbsCommitVerify
    ];


    /// <summary>Gets every operation kind currently registered (built-in plus any added via <see cref="Create"/>).</summary>
    public static IReadOnlyList<CryptographicOperationKind> Kinds => kinds.AsReadOnly();


    /// <summary>
    /// Registers an application-defined operation kind. Use code values
    /// above 1000 to avoid collisions with future library additions; not
    /// thread-safe, call only during application startup.
    /// </summary>
    /// <param name="code">The unique numeric code for the new kind.</param>
    /// <returns>The newly registered kind.</returns>
    /// <exception cref="ArgumentException">When <paramref name="code"/> is already registered.</exception>
    public static CryptographicOperationKind Create(int code)
    {
        for(int i = 0; i < kinds.Count; ++i)
        {
            if(kinds[i].Code == code)
            {
                throw new ArgumentException($"Cryptographic operation kind code {code} already exists.");
            }
        }

        var created = new CryptographicOperationKind(code);
        kinds.Add(created);

        return created;
    }


    /// <inheritdoc/>
    public override string ToString() => CryptographicOperationKindNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CryptographicOperationKind other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is CryptographicOperationKind other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(CryptographicOperationKind left, CryptographicOperationKind right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(CryptographicOperationKind left, CryptographicOperationKind right) => !left.Equals(right);
}


/// <summary>Human-readable names for <see cref="CryptographicOperationKind"/> values.</summary>
public static class CryptographicOperationKindNames
{
    /// <summary>Gets the canonical name for the specified operation kind.</summary>
    public static string GetName(CryptographicOperationKind kind) => GetName(kind.Code);

    /// <summary>Gets the canonical name for the specified operation kind code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == CryptographicOperationKind.None.Code => nameof(CryptographicOperationKind.None),
        var c when c == CryptographicOperationKind.ScalarAdd.Code => nameof(CryptographicOperationKind.ScalarAdd),
        var c when c == CryptographicOperationKind.ScalarSubtract.Code => nameof(CryptographicOperationKind.ScalarSubtract),
        var c when c == CryptographicOperationKind.ScalarMultiply.Code => nameof(CryptographicOperationKind.ScalarMultiply),
        var c when c == CryptographicOperationKind.ScalarNegate.Code => nameof(CryptographicOperationKind.ScalarNegate),
        var c when c == CryptographicOperationKind.ScalarInvert.Code => nameof(CryptographicOperationKind.ScalarInvert),
        var c when c == CryptographicOperationKind.ScalarReduce.Code => nameof(CryptographicOperationKind.ScalarReduce),
        var c when c == CryptographicOperationKind.ScalarRandom.Code => nameof(CryptographicOperationKind.ScalarRandom),
        var c when c == CryptographicOperationKind.ScalarBatchAdd.Code => nameof(CryptographicOperationKind.ScalarBatchAdd),
        var c when c == CryptographicOperationKind.ScalarBatchSubtract.Code => nameof(CryptographicOperationKind.ScalarBatchSubtract),
        var c when c == CryptographicOperationKind.ScalarBatchMultiply.Code => nameof(CryptographicOperationKind.ScalarBatchMultiply),
        var c when c == CryptographicOperationKind.ScalarBatchMultiplyAccumulate.Code => nameof(CryptographicOperationKind.ScalarBatchMultiplyAccumulate),
        var c when c == CryptographicOperationKind.Fp2Add.Code => nameof(CryptographicOperationKind.Fp2Add),
        var c when c == CryptographicOperationKind.Fp2Subtract.Code => nameof(CryptographicOperationKind.Fp2Subtract),
        var c when c == CryptographicOperationKind.Fp2Multiply.Code => nameof(CryptographicOperationKind.Fp2Multiply),
        var c when c == CryptographicOperationKind.Fp2Square.Code => nameof(CryptographicOperationKind.Fp2Square),
        var c when c == CryptographicOperationKind.Fp2Negate.Code => nameof(CryptographicOperationKind.Fp2Negate),
        var c when c == CryptographicOperationKind.Fp2Invert.Code => nameof(CryptographicOperationKind.Fp2Invert),
        var c when c == CryptographicOperationKind.Fp2Conjugate.Code => nameof(CryptographicOperationKind.Fp2Conjugate),
        var c when c == CryptographicOperationKind.G2Add.Code => nameof(CryptographicOperationKind.G2Add),
        var c when c == CryptographicOperationKind.G2Negate.Code => nameof(CryptographicOperationKind.G2Negate),
        var c when c == CryptographicOperationKind.G2ScalarMultiply.Code => nameof(CryptographicOperationKind.G2ScalarMultiply),
        var c when c == CryptographicOperationKind.G2HashToCurve.Code => nameof(CryptographicOperationKind.G2HashToCurve),
        var c when c == CryptographicOperationKind.G2IsOnCurve.Code => nameof(CryptographicOperationKind.G2IsOnCurve),
        var c when c == CryptographicOperationKind.G2IsInPrimeOrderSubgroup.Code => nameof(CryptographicOperationKind.G2IsInPrimeOrderSubgroup),
        var c when c == CryptographicOperationKind.G1Add.Code => nameof(CryptographicOperationKind.G1Add),
        var c when c == CryptographicOperationKind.G1Negate.Code => nameof(CryptographicOperationKind.G1Negate),
        var c when c == CryptographicOperationKind.G1ScalarMultiply.Code => nameof(CryptographicOperationKind.G1ScalarMultiply),
        var c when c == CryptographicOperationKind.G1MultiScalarMultiply.Code => nameof(CryptographicOperationKind.G1MultiScalarMultiply),
        var c when c == CryptographicOperationKind.G1HashToCurve.Code => nameof(CryptographicOperationKind.G1HashToCurve),
        var c when c == CryptographicOperationKind.G1IsOnCurve.Code => nameof(CryptographicOperationKind.G1IsOnCurve),
        var c when c == CryptographicOperationKind.G1IsInPrimeOrderSubgroup.Code => nameof(CryptographicOperationKind.G1IsInPrimeOrderSubgroup),
        var c when c == CryptographicOperationKind.PolynomialEvaluate.Code => nameof(CryptographicOperationKind.PolynomialEvaluate),
        var c when c == CryptographicOperationKind.PolynomialAdd.Code => nameof(CryptographicOperationKind.PolynomialAdd),
        var c when c == CryptographicOperationKind.PolynomialMultiply.Code => nameof(CryptographicOperationKind.PolynomialMultiply),
        var c when c == CryptographicOperationKind.MleFold.Code => nameof(CryptographicOperationKind.MleFold),
        var c when c == CryptographicOperationKind.MleEvaluate.Code => nameof(CryptographicOperationKind.MleEvaluate),
        var c when c == CryptographicOperationKind.TranscriptInitialise.Code => nameof(CryptographicOperationKind.TranscriptInitialise),
        var c when c == CryptographicOperationKind.TranscriptAbsorbBytes.Code => nameof(CryptographicOperationKind.TranscriptAbsorbBytes),
        var c when c == CryptographicOperationKind.TranscriptSqueezeBytes.Code => nameof(CryptographicOperationKind.TranscriptSqueezeBytes),
        var c when c == CryptographicOperationKind.TranscriptUpdateState.Code => nameof(CryptographicOperationKind.TranscriptUpdateState),
        var c when c == CryptographicOperationKind.PedersenCommit.Code => nameof(CryptographicOperationKind.PedersenCommit),
        var c when c == CryptographicOperationKind.HyraxCommit.Code => nameof(CryptographicOperationKind.HyraxCommit),
        var c when c == CryptographicOperationKind.HyraxOpen.Code => nameof(CryptographicOperationKind.HyraxOpen),
        var c when c == CryptographicOperationKind.HyraxVerify.Code => nameof(CryptographicOperationKind.HyraxVerify),
        var c when c == CryptographicOperationKind.IpaProve.Code => nameof(CryptographicOperationKind.IpaProve),
        var c when c == CryptographicOperationKind.IpaVerify.Code => nameof(CryptographicOperationKind.IpaVerify),
        var c when c == CryptographicOperationKind.R1csConstructMatrix.Code => nameof(CryptographicOperationKind.R1csConstructMatrix),
        var c when c == CryptographicOperationKind.R1csMatrixVectorProduct.Code => nameof(CryptographicOperationKind.R1csMatrixVectorProduct),
        var c when c == CryptographicOperationKind.R1csCheckSatisfaction.Code => nameof(CryptographicOperationKind.R1csCheckSatisfaction),
        var c when c == CryptographicOperationKind.RelaxedR1csCheckSatisfaction.Code => nameof(CryptographicOperationKind.RelaxedR1csCheckSatisfaction),
        var c when c == CryptographicOperationKind.RelaxedR1csFold.Code => nameof(CryptographicOperationKind.RelaxedR1csFold),
        var c when c == CryptographicOperationKind.SumcheckRound.Code => nameof(CryptographicOperationKind.SumcheckRound),
        var c when c == CryptographicOperationKind.SparseMatrixMleEvaluate.Code => nameof(CryptographicOperationKind.SparseMatrixMleEvaluate),
        var c when c == CryptographicOperationKind.SpartanVerifierConstruct.Code => nameof(CryptographicOperationKind.SpartanVerifierConstruct),
        var c when c == CryptographicOperationKind.SpartanVerifierVerify.Code => nameof(CryptographicOperationKind.SpartanVerifierVerify),
        var c when c == CryptographicOperationKind.SumcheckRoundVerify.Code => nameof(CryptographicOperationKind.SumcheckRoundVerify),
        var c when c == CryptographicOperationKind.EvalPublicAndOneCompute.Code => nameof(CryptographicOperationKind.EvalPublicAndOneCompute),
        var c when c == CryptographicOperationKind.Fp6Add.Code => nameof(CryptographicOperationKind.Fp6Add),
        var c when c == CryptographicOperationKind.Fp6Subtract.Code => nameof(CryptographicOperationKind.Fp6Subtract),
        var c when c == CryptographicOperationKind.Fp6Multiply.Code => nameof(CryptographicOperationKind.Fp6Multiply),
        var c when c == CryptographicOperationKind.Fp6Square.Code => nameof(CryptographicOperationKind.Fp6Square),
        var c when c == CryptographicOperationKind.Fp6Negate.Code => nameof(CryptographicOperationKind.Fp6Negate),
        var c when c == CryptographicOperationKind.Fp6Invert.Code => nameof(CryptographicOperationKind.Fp6Invert),
        var c when c == CryptographicOperationKind.Fp12Add.Code => nameof(CryptographicOperationKind.Fp12Add),
        var c when c == CryptographicOperationKind.Fp12Subtract.Code => nameof(CryptographicOperationKind.Fp12Subtract),
        var c when c == CryptographicOperationKind.Fp12Multiply.Code => nameof(CryptographicOperationKind.Fp12Multiply),
        var c when c == CryptographicOperationKind.Fp12Square.Code => nameof(CryptographicOperationKind.Fp12Square),
        var c when c == CryptographicOperationKind.Fp12Negate.Code => nameof(CryptographicOperationKind.Fp12Negate),
        var c when c == CryptographicOperationKind.Fp12Invert.Code => nameof(CryptographicOperationKind.Fp12Invert),
        var c when c == CryptographicOperationKind.Fp12Conjugate.Code => nameof(CryptographicOperationKind.Fp12Conjugate),
        var c when c == CryptographicOperationKind.Fp12Frobenius.Code => nameof(CryptographicOperationKind.Fp12Frobenius),
        var c when c == CryptographicOperationKind.Fp12CyclotomicSquare.Code => nameof(CryptographicOperationKind.Fp12CyclotomicSquare),
        var c when c == CryptographicOperationKind.Pairing.Code => nameof(CryptographicOperationKind.Pairing),
        var c when c == CryptographicOperationKind.HashToScalar.Code => nameof(CryptographicOperationKind.HashToScalar),
        var c when c == CryptographicOperationKind.BbsGenerate.Code => nameof(CryptographicOperationKind.BbsGenerate),
        var c when c == CryptographicOperationKind.BbsSign.Code => nameof(CryptographicOperationKind.BbsSign),
        var c when c == CryptographicOperationKind.BbsVerify.Code => nameof(CryptographicOperationKind.BbsVerify),
        var c when c == CryptographicOperationKind.BbsGenerateProof.Code => nameof(CryptographicOperationKind.BbsGenerateProof),
        var c when c == CryptographicOperationKind.BbsVerifyProof.Code => nameof(CryptographicOperationKind.BbsVerifyProof),
        var c when c == CryptographicOperationKind.BbsCommit.Code => nameof(CryptographicOperationKind.BbsCommit),
        var c when c == CryptographicOperationKind.BbsBlindSign.Code => nameof(CryptographicOperationKind.BbsBlindSign),
        var c when c == CryptographicOperationKind.BbsBlindVerify.Code => nameof(CryptographicOperationKind.BbsBlindVerify),
        var c when c == CryptographicOperationKind.BbsBlindGenerateProof.Code => nameof(CryptographicOperationKind.BbsBlindGenerateProof),
        var c when c == CryptographicOperationKind.BbsBlindVerifyProof.Code => nameof(CryptographicOperationKind.BbsBlindVerifyProof),
        var c when c == CryptographicOperationKind.BbsNymCommit.Code => nameof(CryptographicOperationKind.BbsNymCommit),
        var c when c == CryptographicOperationKind.BbsNymBlindSign.Code => nameof(CryptographicOperationKind.BbsNymBlindSign),
        var c when c == CryptographicOperationKind.BbsNymVerifyFinalize.Code => nameof(CryptographicOperationKind.BbsNymVerifyFinalize),
        var c when c == CryptographicOperationKind.BbsNymGenerateProof.Code => nameof(CryptographicOperationKind.BbsNymGenerateProof),
        var c when c == CryptographicOperationKind.BbsNymVerifyProof.Code => nameof(CryptographicOperationKind.BbsNymVerifyProof),
        var c when c == CryptographicOperationKind.BbsCommitVerify.Code => nameof(CryptographicOperationKind.BbsCommitVerify),
        _ => $"Custom ({code})"
    };
}