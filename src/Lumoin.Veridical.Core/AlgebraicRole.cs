using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core;

/// <summary>
/// Identifies the algebraic role a byte buffer plays inside a cryptographic
/// computation: whether it is a scalar, a group element, a polynomial, a
/// commitment, a proof component, and so on.
/// </summary>
/// <remarks>
/// <para>
/// The role is the runtime tag dimension orthogonal to <see cref="CurveParameterSet"/>.
/// Together, an <see cref="AlgebraicRole"/> and a <see cref="CurveParameterSet"/>
/// discriminate every leaf algebraic type the library handles: <c>(Scalar,
/// Bls12Curve381)</c> identifies a BLS12-381 scalar, <c>(G1Point, Bn254)</c>
/// identifies a BN254 G1 point, <c>(PolynomialCoefficients, Pallas)</c>
/// identifies a polynomial whose coefficients live in the Pallas scalar field.
/// </para>
/// <para>
/// The role is enforced by the C# type system at compile time — a
/// <c>Scalar</c> cannot be passed where a <c>G1Point</c> is
/// expected — and again at runtime through the tag, so deserialisation
/// boundaries and dynamic backend dispatch cannot confuse the two.
/// </para>
/// <para>
/// Use <see cref="Create"/> with codes above 1000 to register
/// application-specific roles (a custom commitment family, a research-stage
/// algebraic object).
/// </para>
/// </remarks>
[DebuggerDisplay("{AlgebraicRoleNames.GetName(this),nq}")]
public readonly struct AlgebraicRole: IEquatable<AlgebraicRole>
{
    /// <summary>Gets the numeric code for this algebraic role.</summary>
    public int Code { get; }


    private AlgebraicRole(int code) { Code = code; }


    /// <summary>No specific role.</summary>
    public static AlgebraicRole None { get; } = new(0);

    /// <summary>A scalar in the curve's scalar field.</summary>
    public static AlgebraicRole Scalar { get; } = new(1);

    /// <summary>An element of the curve's base field.</summary>
    public static AlgebraicRole BaseFieldElement { get; } = new(2);

    /// <summary>An element of an extension field over the base field (Fp2, Fp6, Fp12 for pairing curves).</summary>
    public static AlgebraicRole ExtensionFieldElement { get; } = new(3);

    /// <summary>A point on the G1 group of the curve.</summary>
    public static AlgebraicRole G1Point { get; } = new(4);

    /// <summary>A point on the G2 group of the curve (pairing curves only).</summary>
    public static AlgebraicRole G2Point { get; } = new(5);

    /// <summary>An element of the GT target group of a pairing.</summary>
    public static AlgebraicRole GtElement { get; } = new(6);

    /// <summary>A polynomial expressed by its coefficient vector.</summary>
    public static AlgebraicRole PolynomialCoefficients { get; } = new(7);

    /// <summary>A polynomial commitment value bound to a specific commitment scheme.</summary>
    public static AlgebraicRole Commitment { get; } = new(8);

    /// <summary>An opening of a commitment at a specific evaluation point.</summary>
    public static AlgebraicRole Opening { get; } = new(9);

    /// <summary>A proof object that a commitment opens to a claimed evaluation.</summary>
    public static AlgebraicRole EvaluationProof { get; } = new(10);

    /// <summary>A Fiat-Shamir transcript state (the running hash of all protocol messages).</summary>
    public static AlgebraicRole Transcript { get; } = new(11);

    /// <summary>A challenge value derived from a Fiat-Shamir transcript.</summary>
    public static AlgebraicRole Challenge { get; } = new(12);

    /// <summary>A prover's secret key material for a specific proof system instance.</summary>
    public static AlgebraicRole ProvingKey { get; } = new(13);

    /// <summary>A verifier's public key material for a specific proof system instance.</summary>
    public static AlgebraicRole VerificationKey { get; } = new(14);

    /// <summary>A structured reference string (trusted-setup output).</summary>
    public static AlgebraicRole StructuredReferenceString { get; } = new(15);

    /// <summary>The public-input portion of an R1CS instance.</summary>
    public static AlgebraicRole RawR1csInstance { get; } = new(16);

    /// <summary>The witness vector of an R1CS instance.</summary>
    public static AlgebraicRole RawR1csWitness { get; } = new(17);

    /// <summary>A folding-scheme accumulator (relaxed R1CS instance produced by Nova-style folding).</summary>
    public static AlgebraicRole FoldingAccumulator { get; } = new(18);

    /// <summary>A committed lookup table for use with a lookup argument.</summary>
    public static AlgebraicRole LookupTable { get; } = new(19);

    /// <summary>A complete zero-knowledge proof object suitable for serialisation.</summary>
    public static AlgebraicRole ZkProof { get; } = new(20);

    /// <summary>A multilinear extension stored in dense form (2^n evaluations over the boolean hypercube).</summary>
    public static AlgebraicRole MultilinearExtension { get; } = new(21);

    /// <summary>
    /// A Fiat-Shamir transcript state: the accumulated hash state plus
    /// counter that threads through an interactive proof's rounds.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="Transcript"/> (code 11) which is the more
    /// general role for any transcript-like object. The Fiat-Shamir specific
    /// role here lets routing and inspection code recognise the concrete
    /// construction the library lands as a leaf type.
    /// </remarks>
    public static AlgebraicRole FiatShamirTranscript { get; } = new(22);

    /// <summary>
    /// A commitment-scheme public key: the vector of generators (and
    /// auxiliary generators) the scheme commits with. Pedersen-style
    /// schemes derive this deterministically from a seed via
    /// hash-to-curve; KZG-style schemes derive this from a structured
    /// reference string.
    /// </summary>
    public static AlgebraicRole CommitmentKey { get; } = new(23);

    /// <summary>
    /// A polynomial-commitment opening proof. The opening proof, together
    /// with the commitment, attests that the committed polynomial
    /// evaluates to a specific claimed value at a specific evaluation
    /// point.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="EvaluationProof"/> (code 10) which names
    /// the abstract role; the specific commitment-scheme implementations
    /// (Hyrax, KZG, IPA) carry their concrete proof objects under this
    /// role with the scheme discriminator in the Tag.
    /// </remarks>
    public static AlgebraicRole OpeningProof { get; } = new(24);

    /// <summary>
    /// A commitment-scheme prover-side witness: the blinding factors and
    /// any other private state the prover holds alongside a commitment
    /// in order to be able to later open it. The witness is never sent
    /// to the verifier; it lives only on the prover side.
    /// </summary>
    public static AlgebraicRole CommitmentWitness { get; } = new(25);

    /// <summary>
    /// A sparse R1CS coefficient matrix (one of <c>A</c>, <c>B</c>, or <c>C</c>).
    /// </summary>
    public static AlgebraicRole R1csMatrix { get; } = new(26);

    /// <summary>
    /// A sumcheck round polynomial in compressed form, with the linear
    /// coefficient elided and reconstructed at decompress time from the
    /// running claim.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="PolynomialCoefficients"/> (code 7) because
    /// the buffer layout is different — a degree-<c>d</c> compressed round
    /// polynomial holds <c>d</c> field elements rather than <c>d + 1</c>,
    /// and slot indices skip the linear term. Decoders that operate on
    /// raw coefficient bytes must dispatch on this role.
    /// </remarks>
    public static AlgebraicRole CompressedRoundPolynomial { get; } = new(27);

    /// <summary>
    /// A single round of the sumcheck protocol: the prover's round
    /// polynomial (compressed) and the verifier's challenge.
    /// </summary>
    public static AlgebraicRole SumcheckRound { get; } = new(28);

    /// <summary>
    /// The secret-key half of a signature scheme's key pair.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="ProvingKey"/> (code 13), which names the
    /// abstract prover-side role for a proof-system instance — signature
    /// schemes are a more specific construction. The concrete scheme
    /// (BBS+, Schnorr, ECDSA, ...) is identified by an entry in the tag
    /// separate from the algebraic role, exactly as <see cref="Commitment"/>
    /// (code 8) is qualified by an entry of type <c>CommitmentScheme</c>.
    /// </remarks>
    public static AlgebraicRole SignatureSecretKey { get; } = new(29);

    /// <summary>
    /// The public-key half of a signature scheme's key pair.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="VerificationKey"/> (code 14), which names
    /// the abstract verifier-side role for a proof-system instance. The
    /// concrete scheme is identified by an entry in the tag separate from
    /// the algebraic role.
    /// </remarks>
    public static AlgebraicRole SignaturePublicKey { get; } = new(30);

    /// <summary>
    /// A produced signature value over some message vector.
    /// </summary>
    /// <remarks>
    /// The signature's exact wire shape depends on the scheme (BBS+ is
    /// an Fp scalar plus a G1 point, Schnorr is two Fp scalars, ECDSA is
    /// two Fp scalars). The scheme is identified by an entry in the tag.
    /// </remarks>
    public static AlgebraicRole Signature { get; } = new(31);


    private static readonly List<AlgebraicRole> roles =
    [
        None,
        Scalar,
        BaseFieldElement,
        ExtensionFieldElement,
        G1Point,
        G2Point,
        GtElement,
        PolynomialCoefficients,
        Commitment,
        Opening,
        EvaluationProof,
        Transcript,
        Challenge,
        ProvingKey,
        VerificationKey,
        StructuredReferenceString,
        RawR1csInstance,
        RawR1csWitness,
        FoldingAccumulator,
        LookupTable,
        ZkProof,
        MultilinearExtension,
        FiatShamirTranscript,
        CommitmentKey,
        OpeningProof,
        CommitmentWitness,
        R1csMatrix,
        CompressedRoundPolynomial,
        SumcheckRound,
        SignatureSecretKey,
        SignaturePublicKey,
        Signature
    ];


    /// <summary>Gets all registered algebraic role values.</summary>
    public static IReadOnlyList<AlgebraicRole> Roles => roles.AsReadOnly();


    /// <summary>
    /// Creates a new algebraic role value for application-specific extensions.
    /// </summary>
    /// <param name="code">The unique numeric code for this role.</param>
    /// <returns>The newly created algebraic role.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Use code values above 1000 to avoid collisions with future library
    /// additions. This method is not thread-safe; call it only during
    /// application startup before concurrent access begins.
    /// </remarks>
    public static AlgebraicRole Create(int code)
    {
        for(int i = 0; i < roles.Count; ++i)
        {
            if(roles[i].Code == code)
            {
                throw new ArgumentException($"Algebraic role code {code} already exists.");
            }
        }

        var created = new AlgebraicRole(code);
        roles.Add(created);

        return created;
    }


    /// <inheritdoc/>
    public override string ToString() => AlgebraicRoleNames.GetName(this);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(AlgebraicRole other) => Code == other.Code;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is AlgebraicRole other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;

    /// <inheritdoc/>
    public static bool operator ==(AlgebraicRole left, AlgebraicRole right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(AlgebraicRole left, AlgebraicRole right) => !left.Equals(right);
}


/// <summary>Provides human-readable names for <see cref="AlgebraicRole"/> values.</summary>
public static class AlgebraicRoleNames
{
    /// <summary>Gets the name for the specified algebraic role.</summary>
    public static string GetName(AlgebraicRole role) => GetName(role.Code);

    /// <summary>Gets the name for the specified algebraic role code.</summary>
    public static string GetName(int code) => code switch
    {
        var c when c == AlgebraicRole.None.Code => nameof(AlgebraicRole.None),
        var c when c == AlgebraicRole.Scalar.Code => nameof(AlgebraicRole.Scalar),
        var c when c == AlgebraicRole.BaseFieldElement.Code => nameof(AlgebraicRole.BaseFieldElement),
        var c when c == AlgebraicRole.ExtensionFieldElement.Code => nameof(AlgebraicRole.ExtensionFieldElement),
        var c when c == AlgebraicRole.G1Point.Code => nameof(AlgebraicRole.G1Point),
        var c when c == AlgebraicRole.G2Point.Code => nameof(AlgebraicRole.G2Point),
        var c when c == AlgebraicRole.GtElement.Code => nameof(AlgebraicRole.GtElement),
        var c when c == AlgebraicRole.PolynomialCoefficients.Code => nameof(AlgebraicRole.PolynomialCoefficients),
        var c when c == AlgebraicRole.Commitment.Code => nameof(AlgebraicRole.Commitment),
        var c when c == AlgebraicRole.Opening.Code => nameof(AlgebraicRole.Opening),
        var c when c == AlgebraicRole.EvaluationProof.Code => nameof(AlgebraicRole.EvaluationProof),
        var c when c == AlgebraicRole.Transcript.Code => nameof(AlgebraicRole.Transcript),
        var c when c == AlgebraicRole.Challenge.Code => nameof(AlgebraicRole.Challenge),
        var c when c == AlgebraicRole.ProvingKey.Code => nameof(AlgebraicRole.ProvingKey),
        var c when c == AlgebraicRole.VerificationKey.Code => nameof(AlgebraicRole.VerificationKey),
        var c when c == AlgebraicRole.StructuredReferenceString.Code => nameof(AlgebraicRole.StructuredReferenceString),
        var c when c == AlgebraicRole.RawR1csInstance.Code => nameof(AlgebraicRole.RawR1csInstance),
        var c when c == AlgebraicRole.RawR1csWitness.Code => nameof(AlgebraicRole.RawR1csWitness),
        var c when c == AlgebraicRole.FoldingAccumulator.Code => nameof(AlgebraicRole.FoldingAccumulator),
        var c when c == AlgebraicRole.LookupTable.Code => nameof(AlgebraicRole.LookupTable),
        var c when c == AlgebraicRole.ZkProof.Code => nameof(AlgebraicRole.ZkProof),
        var c when c == AlgebraicRole.MultilinearExtension.Code => nameof(AlgebraicRole.MultilinearExtension),
        var c when c == AlgebraicRole.FiatShamirTranscript.Code => nameof(AlgebraicRole.FiatShamirTranscript),
        var c when c == AlgebraicRole.CommitmentKey.Code => nameof(AlgebraicRole.CommitmentKey),
        var c when c == AlgebraicRole.OpeningProof.Code => nameof(AlgebraicRole.OpeningProof),
        var c when c == AlgebraicRole.CommitmentWitness.Code => nameof(AlgebraicRole.CommitmentWitness),
        var c when c == AlgebraicRole.R1csMatrix.Code => nameof(AlgebraicRole.R1csMatrix),
        var c when c == AlgebraicRole.CompressedRoundPolynomial.Code => nameof(AlgebraicRole.CompressedRoundPolynomial),
        var c when c == AlgebraicRole.SumcheckRound.Code => nameof(AlgebraicRole.SumcheckRound),
        var c when c == AlgebraicRole.SignatureSecretKey.Code => nameof(AlgebraicRole.SignatureSecretKey),
        var c when c == AlgebraicRole.SignaturePublicKey.Code => nameof(AlgebraicRole.SignaturePublicKey),
        var c when c == AlgebraicRole.Signature.Code => nameof(AlgebraicRole.Signature),
        _ => $"Custom ({code})"
    };
}