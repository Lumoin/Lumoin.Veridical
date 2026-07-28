using System;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The span revocation statement's shared shape constants, a faithful port of google/longfellow-zk's
/// <c>circuits/tests/mdoc/mdoc_revocation_constants.h</c> and the span layout its classes fix inline.
/// </summary>
internal static class LongfellowMdocRevocationConstants
{
    /// <summary>The SHA-256 witness packing width the span statement uses (the reference's <c>kSHARevocationPluckerBits</c>).</summary>
    public const int ShaRevocationPluckerBits = 4;

    /// <summary>The span preimage's fixed capacity in SHA-256 blocks: the 72-byte span plus padding always occupies two blocks.</summary>
    public const int SpanBlockCount = 2;

    /// <summary>The signed span's byte length: an eight-byte epoch and two 256-bit bounds, all little endian.</summary>
    public const int SpanMessageLength = EpochByteLength + (2 * BoundByteLength);

    /// <summary>The epoch's byte length inside the span.</summary>
    public const int EpochByteLength = 8;

    /// <summary>One span bound's byte length.</summary>
    public const int BoundByteLength = 32;

    /// <summary>The lower bound's byte offset inside the span (right after the epoch).</summary>
    public const int LowerBoundByteOffset = EpochByteLength;

    /// <summary>The upper bound's byte offset inside the span.</summary>
    public const int UpperBoundByteOffset = EpochByteLength + BoundByteLength;
}


/// <summary>
/// The private witness wires of the span revocation statement, a faithful port of the reference's
/// <c>MdocRevocationSpan::Witness</c>: the span signature's scalars and ECDSA advice, the padded
/// span preimage, the identifier and digest bits, and the two-block SHA-256 advice.
/// </summary>
internal sealed class LongfellowMdocRevocationSpanWitnessWires
{
    /// <summary>The span signature's <c>r</c> wire: declared and filled but deliberately unconsumed by the statement, exactly as in the reference — the signature scalars the verification gadget uses live inside the advice bundle.</summary>
    public int R { get; }

    /// <summary>The span signature's <c>s</c> wire: declared and filled but deliberately unconsumed, like <see cref="R"/>.</summary>
    public int S { get; }

    /// <summary>The span digest wire the signature verification consumes.</summary>
    public int E { get; }

    /// <summary>The span signature's ECDSA advice.</summary>
    public LongfellowEcdsaVerifyWitnessWires RevocationSignature { get; }

    /// <summary>The padded span preimage's bytes as eight-bit vectors.</summary>
    public LongfellowBitWire[][] Preimage { get; }

    /// <summary>The credential identifier's 256 bits, least significant first.</summary>
    public LongfellowBitWire[] IdBits { get; }

    /// <summary>The span digest's 256 bits, least significant first.</summary>
    public LongfellowBitWire[] EBits { get; }

    /// <summary>The per-block SHA-256 advice.</summary>
    public LongfellowFlatSha256PackedBlockWitness[] Sha { get; }


    /// <summary>
    /// Constructs the bundle from already-produced wires.
    /// </summary>
    /// <param name="r">The signature's <c>r</c> wire.</param>
    /// <param name="s">The signature's <c>s</c> wire.</param>
    /// <param name="e">The digest wire.</param>
    /// <param name="revocationSignature">The signature advice.</param>
    /// <param name="preimage">The preimage byte vectors.</param>
    /// <param name="idBits">The identifier bits.</param>
    /// <param name="eBits">The digest bits.</param>
    /// <param name="sha">The SHA-256 block advice.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public LongfellowMdocRevocationSpanWitnessWires(
        int r,
        int s,
        int e,
        LongfellowEcdsaVerifyWitnessWires revocationSignature,
        LongfellowBitWire[][] preimage,
        LongfellowBitWire[] idBits,
        LongfellowBitWire[] eBits,
        LongfellowFlatSha256PackedBlockWitness[] sha)
    {
        ArgumentNullException.ThrowIfNull(revocationSignature);
        ArgumentNullException.ThrowIfNull(preimage);
        ArgumentNullException.ThrowIfNull(idBits);
        ArgumentNullException.ThrowIfNull(eBits);
        ArgumentNullException.ThrowIfNull(sha);

        R = r;
        S = s;
        E = e;
        RevocationSignature = revocationSignature;
        Preimage = preimage;
        IdBits = idBits;
        EBits = eBits;
        Sha = sha;
    }
}


/// <summary>
/// The span revocation statement circuit, a faithful port of google/longfellow-zk's
/// <c>MdocRevocationSpan</c> (<c>circuits/tests/mdoc/mdoc_revocation.h</c>): the revocation
/// authority signs spans <c>epoch || l || r</c> of consecutive revoked-identifier gaps, and the
/// prover shows their identifier is unrevoked by verifying one span signature and proving
/// <c>l &lt; id &lt; r</c> — strict on both sides, so a revoked identifier, which sits at a span
/// endpoint, cannot satisfy the statement.
/// </summary>
/// <remarks>
/// <para>
/// The range check runs over <c>IdBits</c>, the identifier's private witness bits; the separate
/// identifier element the statement's caller declares is deliberately unconsumed, exactly as in
/// the reference. Tying the range-checked bits to any outer identifier element or commitment is
/// therefore a prover-side convention — a relying party that needs the binding must add it outside
/// this statement, precisely like the JWT statement's <c>cnf</c> device-key note.
/// </para>
/// <para>
/// The epoch is signed inside the span but never exposed as a public input: the statement proves
/// the identifier lies inside SOME span the authority signed, not a span from any particular list
/// epoch. Freshness enforcement — rejecting proofs built on stale spans — likewise lives outside
/// the statement, exactly as in the reference.
/// </para>
/// </remarks>
internal sealed class LongfellowMdocRevocationSpanCircuit
{
    /// <summary>One SHA-256 block's byte width.</summary>
    private const int BytesPerBlock = 64;

    private readonly LongfellowLogic logic;
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowLogicFieldOperations field;
    private readonly LongfellowEllipticCurveParameters curve;
    private readonly LongfellowFlatSha256Circuit sha;


    /// <summary>
    /// Constructs the statement over a gadget layer and a curve, building the SHA-256 gadget at the
    /// revocation packing width (the reference constructor's member initialization).
    /// </summary>
    /// <param name="logic">The gadget layer every sub-circuit builds on.</param>
    /// <param name="curve">The curve constants.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> or <paramref name="curve"/> is <see langword="null"/>.</exception>
    public LongfellowMdocRevocationSpanCircuit(LongfellowLogic logic, LongfellowEllipticCurveParameters curve)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentNullException.ThrowIfNull(curve);

        this.logic = logic;
        this.curve = curve;
        backend = logic.Backend;
        field = logic.Field;
        sha = new LongfellowFlatSha256Circuit(logic, new LongfellowBitPlucker(logic, LongfellowMdocRevocationConstants.ShaRevocationPluckerBits));
    }


    /// <summary>
    /// The reference's <c>Witness::input</c>: declares every private witness wire in the reference
    /// order — the signature scalars and span digest, the ECDSA advice, the preimage bytes, the
    /// identifier bits, the digest bits, and the two SHA-256 block advice bundles.
    /// </summary>
    /// <returns>The declared bundle.</returns>
    public LongfellowMdocRevocationSpanWitnessWires InputWitness()
    {
        int r = logic.InputElement();
        int s = logic.InputElement();
        int e = logic.InputElement();
        LongfellowEcdsaVerifyWitnessWires revocationSignature = LongfellowEcdsaVerifyWitnessWires.Input(logic, curve.ScalarBitCount);

        var preimage = new LongfellowBitWire[LongfellowMdocRevocationConstants.SpanBlockCount * BytesPerBlock][];
        for(int i = 0; i < preimage.Length; i++)
        {
            preimage[i] = logic.InputVector(LongfellowLogic.BitWidth8);
        }

        LongfellowBitWire[] idBits = logic.InputVector(LongfellowLogic.BitWidth256);
        LongfellowBitWire[] eBits = logic.InputVector(LongfellowLogic.BitWidth256);

        var shaWitness = new LongfellowFlatSha256PackedBlockWitness[LongfellowMdocRevocationConstants.SpanBlockCount];
        for(int j = 0; j < shaWitness.Length; j++)
        {
            shaWitness[j] = new LongfellowFlatSha256PackedBlockWitness();
            shaWitness[j].Input(sha);
        }

        return new LongfellowMdocRevocationSpanWitnessWires(r, s, e, revocationSignature, preimage, idBits, eBits, shaWitness);
    }


    /// <summary>
    /// The reference's <c>assert_not_on_list</c>: verifies the revocation authority's signature on
    /// the span, ties the span's SHA-256 digest to the signature bit for bit, and asserts the
    /// identifier lies strictly inside the span's bounds.
    /// </summary>
    /// <param name="craPkX">The revocation authority public key's x coordinate wire (public).</param>
    /// <param name="craPkY">The revocation authority public key's y coordinate wire (public).</param>
    /// <param name="id">The identifier element wire (private): declared by the caller and deliberately unconsumed here, exactly as in the reference — the range check runs over <see cref="LongfellowMdocRevocationSpanWitnessWires.IdBits"/> (see the class remarks).</param>
    /// <param name="witness">The private witness wires.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="witness"/> is <see langword="null"/>.</exception>
    public void AssertNotOnList(int craPkX, int craPkY, int id, LongfellowMdocRevocationSpanWitnessWires witness)
    {
        ArgumentNullException.ThrowIfNull(witness);

        var ecdsa = new LongfellowEcdsaVerifyCircuit(logic, curve);
        ecdsa.VerifySignature3(craPkX, craPkY, witness.E, witness.RevocationSignature);

        logic.AssertIsBit(witness.EBits);
        logic.AssertIsBit(witness.IdBits);

        //The span always pads to exactly two occupied blocks, so the block count is a constant.
        LongfellowBitWire[] blockCount = logic.BitVector(LongfellowLogic.BitWidth8, LongfellowMdocRevocationConstants.SpanBlockCount);
        sha.AssertMessageHash(LongfellowMdocRevocationConstants.SpanBlockCount, blockCount, witness.Preimage, witness.EBits, witness.Sha);

        //Recompose the digest bits into a field element and tie it to the signature's digest; this
        //is also what guarantees e is nonzero advice-independently.
        ReadOnlyMemory<byte> powerOfTwo = field.Compiler.One;
        int est = backend.Constant(field.Compiler.Zero.Span);
        for(int i = 0; i < LongfellowLogic.BitWidth256; i++)
        {
            est = backend.Axpy(est, powerOfTwo.Span, logic.Eval(witness.EBits[i]));

            var doubled = new byte[Scalar.SizeBytes];
            field.Compiler.Add(powerOfTwo.Span, powerOfTwo.Span, doubled, field.Compiler.Curve);
            powerOfTwo = doubled;
        }

        _ = logic.AssertEqual(est, witness.E);

        //The bounds sit inside the signed span at fixed little-endian offsets, so their bits are
        //read straight out of the preimage bytes the digest check already constrains.
        var lowerBound = new LongfellowBitWire[LongfellowLogic.BitWidth256];
        var upperBound = new LongfellowBitWire[LongfellowLogic.BitWidth256];
        for(int i = 0; i < LongfellowLogic.BitWidth256; i++)
        {
            lowerBound[i] = witness.Preimage[LongfellowMdocRevocationConstants.LowerBoundByteOffset + (i / LongfellowLogic.BitWidth8)][i % LongfellowLogic.BitWidth8];
            upperBound[i] = witness.Preimage[LongfellowMdocRevocationConstants.UpperBoundByteOffset + (i / LongfellowLogic.BitWidth8)][i % LongfellowLogic.BitWidth8];
        }

        _ = logic.AssertOne(logic.LessThan(lowerBound, witness.IdBits));
        _ = logic.AssertOne(logic.LessThan(witness.IdBits, upperBound));
    }
}
