using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A BBS+ selective-disclosure proof: the variable-length byte
/// composition <c>(Abar, Bbar, D, e^, r1^, r3^, m^_j1, ..., m^_jU, c)</c>
/// per IETF <c>draft-irtf-cfrg-bbs-signatures-10</c> Section 3.5.3
/// (Proof to Octets). Pool-rented buffer, runtime-tagged with the
/// BBS+ ciphersuite identifier and the zero-knowledge-proof
/// algebraic role.
/// </summary>
/// <remarks>
/// <para>
/// The proof's byte length is fixed once the number of undisclosed
/// messages is known: <c>3 * 48 (Abar, Bbar, D) + 4 * 32 (e^, r1^, r3^, c)
/// + 32 * U</c> where <c>U</c> is the count of undisclosed messages.
/// A proof that discloses every message has <c>U = 0</c> and a fixed
/// 272-byte size; a proof over a 100-message vector that discloses
/// none has <c>U = 100</c> and a 3472-byte size.
/// </para>
/// <para>
/// The undisclosed-message count is recovered from the byte length
/// rather than stored separately, exactly as the spec's
/// <c>octets_to_proof</c> deserialisation does. The
/// <see cref="UndisclosedMessageCount"/> property exposes that recovered
/// value as a convenience.
/// </para>
/// </remarks>
public sealed class BbsProof: SensitiveMemory
{
    /// <summary>The canonical byte length of the G1 component <c>Abar</c>.</summary>
    public const int ABarSizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>The canonical byte length of the G1 component <c>Bbar</c>.</summary>
    public const int BBarSizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>The canonical byte length of the G1 component <c>D</c>.</summary>
    public const int DSizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>The canonical byte length of each scalar slot.</summary>
    public const int ScalarSizeBytes = WellKnownCurves.Bls12Curve381ScalarSizeBytes;


    /// <summary>The byte offset of the G1 component <c>Abar</c>.</summary>
    public const int ABarOffset = 0;

    /// <summary>The byte offset of the G1 component <c>Bbar</c>.</summary>
    public const int BBarOffset = ABarOffset + ABarSizeBytes;

    /// <summary>The byte offset of the G1 component <c>D</c>.</summary>
    public const int DOffset = BBarOffset + BBarSizeBytes;

    /// <summary>The byte offset of the scalar <c>e^</c>.</summary>
    public const int EHatOffset = DOffset + DSizeBytes;

    /// <summary>The byte offset of the scalar <c>r1^</c>.</summary>
    public const int R1HatOffset = EHatOffset + ScalarSizeBytes;

    /// <summary>The byte offset of the scalar <c>r3^</c>.</summary>
    public const int R3HatOffset = R1HatOffset + ScalarSizeBytes;

    /// <summary>The byte offset of the first message-commitment scalar (if any).</summary>
    public const int CommitmentsOffset = R3HatOffset + ScalarSizeBytes;


    /// <summary>The byte length of a proof with zero undisclosed messages (3 G1 points + 4 scalars).</summary>
    public const int MinimumSizeBytes = 3 * ABarSizeBytes + 4 * ScalarSizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256);


    /// <summary>The BBS+ ciphersuite this proof was produced under (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    /// <summary>
    /// Returns the shared algebraic-identity tag every BBS+ proof
    /// under <paramref name="ciphersuite"/> carries:
    /// zero-knowledge-proof role, BLS12-381 curve, the supplied
    /// ciphersuite.
    /// </summary>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not a known well-known ciphersuite.</exception>
    public static Tag GetAlgebraicTag(BbsCiphersuite ciphersuite)
    {
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256)
        {
            return AlgebraicTagSha256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256)
        {
            return AlgebraicTagShake256;
        }
        throw new ArgumentException($"Unknown BBS+ ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }


    /// <summary>The number of undisclosed messages — recovered from the byte length.</summary>
    public int UndisclosedMessageCount { get; }


    internal BbsProof(IMemoryOwner<byte> owner, int undisclosedMessageCount, Tag tag)
        : base(owner, tag)
    {
        UndisclosedMessageCount = undisclosedMessageCount;
    }


    /// <summary>
    /// Returns the byte length of a BBS+ proof with
    /// <paramref name="undisclosedMessageCount"/> undisclosed messages.
    /// </summary>
    /// <param name="undisclosedMessageCount">Non-negative integer.</param>
    /// <returns><c>272 + 32 * undisclosedMessageCount</c>.</returns>
    public static int ComputeSizeBytes(int undisclosedMessageCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(undisclosedMessageCount);
        return MinimumSizeBytes + ScalarSizeBytes * undisclosedMessageCount;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented
    /// buffer and returns a proof wrapping it. The undisclosed-
    /// message count is recovered from the byte length per the
    /// spec's <c>octets_to_proof</c> deserialisation.
    /// </summary>
    /// <param name="canonicalBytes">At least <see cref="MinimumSizeBytes"/> bytes; the difference from the minimum must be a multiple of <see cref="ScalarSizeBytes"/>.</param>
    /// <param name="ciphersuite">The BBS ciphersuite.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A proof wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> is shorter than <see cref="MinimumSizeBytes"/>, its length above the minimum is not a multiple of <see cref="ScalarSizeBytes"/>, or any scalar component is zero or not below the scalar field order.</exception>
    public static BbsProof FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(canonicalBytes.Length < MinimumSizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ proof must be at least {MinimumSizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }
        int extra = canonicalBytes.Length - MinimumSizeBytes;
        if(extra % ScalarSizeBytes != 0)
        {
            throw new ArgumentException(
                $"BBS+ proof length above the minimum ({extra} bytes) must be a multiple of the scalar length ({ScalarSizeBytes}).",
                nameof(canonicalBytes));
        }
        int undisclosed = extra / ScalarSizeBytes;

        //The spec's octets_to_proof: every scalar component (e^, r1^, r3^, the
        //m^_j commitments, and the challenge c) must be in [1, r-1]. Everything
        //after the three G1 points is a 32-byte scalar slot, so one pass covers
        //them all; the points are validated (on-curve, non-identity, prime-order
        //subgroup) at the VerifyProof surface before any MSM.
        for(int offset = EHatOffset; offset < canonicalBytes.Length; offset += ScalarSizeBytes)
        {
            ReadOnlySpan<byte> scalar = canonicalBytes.Slice(offset, ScalarSizeBytes);
            if(!WellKnownCurves.IsCanonicalScalar(scalar, CurveParameterSet.Bls12Curve381) || scalar.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    $"BBS+ proof scalar at byte offset {offset} must be in [1, r-1]; received zero or a value at or above the scalar field order.",
                    nameof(canonicalBytes));
            }
        }

        IMemoryOwner<byte> owner = pool.Rent(canonicalBytes.Length);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsProof(owner, undisclosed, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the G1 component <c>Abar</c>.</summary>
    public ReadOnlySpan<byte> GetABarBytes() => AsReadOnlySpan().Slice(ABarOffset, ABarSizeBytes);

    /// <summary>Returns the canonical bytes of the G1 component <c>Bbar</c>.</summary>
    public ReadOnlySpan<byte> GetBBarBytes() => AsReadOnlySpan().Slice(BBarOffset, BBarSizeBytes);

    /// <summary>Returns the canonical bytes of the G1 component <c>D</c>.</summary>
    public ReadOnlySpan<byte> GetDBytes() => AsReadOnlySpan().Slice(DOffset, DSizeBytes);

    /// <summary>Returns the canonical bytes of the scalar <c>e^</c>.</summary>
    public ReadOnlySpan<byte> GetEHatBytes() => AsReadOnlySpan().Slice(EHatOffset, ScalarSizeBytes);

    /// <summary>Returns the canonical bytes of the scalar <c>r1^</c>.</summary>
    public ReadOnlySpan<byte> GetR1HatBytes() => AsReadOnlySpan().Slice(R1HatOffset, ScalarSizeBytes);

    /// <summary>Returns the canonical bytes of the scalar <c>r3^</c>.</summary>
    public ReadOnlySpan<byte> GetR3HatBytes() => AsReadOnlySpan().Slice(R3HatOffset, ScalarSizeBytes);

    /// <summary>Returns the canonical bytes of the <paramref name="index"/>-th undisclosed-message commitment <c>m^_j</c>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public ReadOnlySpan<byte> GetCommitmentBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, UndisclosedMessageCount);
        return AsReadOnlySpan().Slice(CommitmentsOffset + ScalarSizeBytes * index, ScalarSizeBytes);
    }

    /// <summary>Returns the canonical bytes of the challenge scalar <c>c</c>.</summary>
    public ReadOnlySpan<byte> GetChallengeBytes() =>
        AsReadOnlySpan().Slice(CommitmentsOffset + ScalarSizeBytes * UndisclosedMessageCount, ScalarSizeBytes);


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.ZkProof)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}