using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A per-verifier-pseudonym BBS selective-disclosure proof: the same
/// variable-length byte composition as <see cref="BbsProof"/>
/// (<c>Abar, Bbar, D, e^, r1^, r3^, m^_j1, ..., m^_jU, c</c>) — IETF
/// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section 8
/// confirms the nym proof octets ARE the core BBS+ proof layout, with
/// no additional framing. The pseudonym itself travels alongside this
/// proof as a separate value (see <see cref="BbsPseudonym"/>); it is not
/// concatenated into these octets.
/// </summary>
/// <remarks>
/// A distinct type from <see cref="BbsProof"/> even though the wire
/// shape and offset arithmetic are identical: a nym proof is produced by
/// <c>ProofGenWithNym</c> and verified by <c>ProofVerifyWithNym</c> under
/// the per-verifier-pseudonym Interface api_id, which changes the
/// generator set, the <c>combined_header</c> (binds
/// <c>length_nym_vector</c>), and the challenge computation (binds the
/// pseudonym and <c>Ut</c>) relative to core BBS+ <c>ProofGen</c>/
/// <c>ProofVerify</c>. This class reuses <see cref="BbsProof"/>'s own
/// offset and size constants directly (<see cref="BbsProof.ABarOffset"/>,
/// <see cref="BbsProof.EHatOffset"/>, <see cref="BbsProof.ScalarSizeBytes"/>,
/// and so on) rather than re-declaring an identical set, since the wire
/// layout genuinely is the same; only the Interface — carried in the
/// <see cref="Ciphersuite"/> tag — differs.
/// </remarks>
public sealed class BbsPseudonymProof: SensitiveMemory
{
    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256Pseudonym);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256Pseudonym);


    /// <summary>The per-verifier-pseudonym Interface this proof was produced under (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    /// <summary>
    /// Returns the shared algebraic-identity tag every nym proof under
    /// <paramref name="ciphersuite"/> carries: zero-knowledge-proof role,
    /// BLS12-381 curve, the per-verifier-pseudonym Interface.
    /// </summary>
    /// <param name="ciphersuite">Either <see cref="BbsCiphersuite.Bls12Curve381Sha256Pseudonym"/> or <see cref="BbsCiphersuite.Bls12Curve381Shake256Pseudonym"/>.</param>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not one of the two per-verifier-pseudonym Interface values.</exception>
    public static Tag GetAlgebraicTag(BbsCiphersuite ciphersuite)
    {
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256Pseudonym)
        {
            return AlgebraicTagSha256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256Pseudonym)
        {
            return AlgebraicTagShake256;
        }
        throw new ArgumentException($"Unknown per-verifier-pseudonym Interface ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }


    /// <summary>The number of undisclosed messages — recovered from the byte length, exactly as <see cref="BbsProof.UndisclosedMessageCount"/> is.</summary>
    public int UndisclosedMessageCount { get; }


    internal BbsPseudonymProof(IMemoryOwner<byte> owner, int undisclosedMessageCount, Tag tag)
        : base(owner, tag)
    {
        UndisclosedMessageCount = undisclosedMessageCount;
    }


    /// <summary>
    /// Returns the byte length of a nym proof with
    /// <paramref name="undisclosedMessageCount"/> undisclosed messages —
    /// identical to <see cref="BbsProof.ComputeSizeBytes"/>.
    /// </summary>
    public static int ComputeSizeBytes(int undisclosedMessageCount) => BbsProof.ComputeSizeBytes(undisclosedMessageCount);


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer
    /// and returns a nym proof wrapping it. The undisclosed-message count
    /// is recovered from the byte length, and every scalar slot is
    /// validated canonical-nonzero, exactly as
    /// <see cref="BbsProof.FromCanonical"/> does.
    /// </summary>
    /// <param name="canonicalBytes">At least <see cref="BbsProof.MinimumSizeBytes"/> bytes; the difference from the minimum must be a multiple of <see cref="BbsProof.ScalarSizeBytes"/>.</param>
    /// <param name="ciphersuite">The per-verifier-pseudonym Interface ciphersuite.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A nym proof wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> is shorter than <see cref="BbsProof.MinimumSizeBytes"/>, its length above the minimum is not a multiple of <see cref="BbsProof.ScalarSizeBytes"/>, or any scalar component is zero or not below the scalar field order.</exception>
    public static BbsPseudonymProof FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(canonicalBytes.Length < BbsProof.MinimumSizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ nym proof must be at least {BbsProof.MinimumSizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }
        int extra = canonicalBytes.Length - BbsProof.MinimumSizeBytes;
        if(extra % BbsProof.ScalarSizeBytes != 0)
        {
            throw new ArgumentException(
                $"BBS+ nym proof length above the minimum ({extra} bytes) must be a multiple of the scalar length ({BbsProof.ScalarSizeBytes}).",
                nameof(canonicalBytes));
        }
        int undisclosed = extra / BbsProof.ScalarSizeBytes;

        //Mirrors BbsProof.FromCanonical's own scalar-canonicity loop exactly:
        //every scalar slot (e^, r1^, r3^, the m^_j commitments, and the
        //challenge) must be in [1, r-1]. The three G1 points are validated at
        //the operation surfaces before any MSM, matching the house pattern.
        for(int offset = BbsProof.EHatOffset; offset < canonicalBytes.Length; offset += BbsProof.ScalarSizeBytes)
        {
            ReadOnlySpan<byte> scalar = canonicalBytes.Slice(offset, BbsProof.ScalarSizeBytes);
            if(!WellKnownCurves.IsCanonicalScalar(scalar, CurveParameterSet.Bls12Curve381) || scalar.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    $"BBS+ nym proof scalar at byte offset {offset} must be in [1, r-1]; received zero or a value at or above the scalar field order.",
                    nameof(canonicalBytes));
            }
        }

        IMemoryOwner<byte> owner = pool.Rent(canonicalBytes.Length);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsPseudonymProof(owner, undisclosed, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the G1 component <c>Abar</c>.</summary>
    public ReadOnlySpan<byte> GetABarBytes() => AsReadOnlySpan().Slice(BbsProof.ABarOffset, BbsProof.ABarSizeBytes);

    /// <summary>Returns the canonical bytes of the G1 component <c>Bbar</c>.</summary>
    public ReadOnlySpan<byte> GetBBarBytes() => AsReadOnlySpan().Slice(BbsProof.BBarOffset, BbsProof.BBarSizeBytes);

    /// <summary>Returns the canonical bytes of the G1 component <c>D</c>.</summary>
    public ReadOnlySpan<byte> GetDBytes() => AsReadOnlySpan().Slice(BbsProof.DOffset, BbsProof.DSizeBytes);

    /// <summary>Returns the canonical bytes of the scalar <c>e^</c>.</summary>
    public ReadOnlySpan<byte> GetEHatBytes() => AsReadOnlySpan().Slice(BbsProof.EHatOffset, BbsProof.ScalarSizeBytes);

    /// <summary>Returns the canonical bytes of the scalar <c>r1^</c>.</summary>
    public ReadOnlySpan<byte> GetR1HatBytes() => AsReadOnlySpan().Slice(BbsProof.R1HatOffset, BbsProof.ScalarSizeBytes);

    /// <summary>Returns the canonical bytes of the scalar <c>r3^</c>.</summary>
    public ReadOnlySpan<byte> GetR3HatBytes() => AsReadOnlySpan().Slice(BbsProof.R3HatOffset, BbsProof.ScalarSizeBytes);

    /// <summary>Returns the canonical bytes of the <paramref name="index"/>-th undisclosed-message commitment <c>m^_j</c>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public ReadOnlySpan<byte> GetCommitmentBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, UndisclosedMessageCount);
        return AsReadOnlySpan().Slice(BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes * index, BbsProof.ScalarSizeBytes);
    }

    /// <summary>Returns the canonical bytes of the challenge scalar <c>c</c>.</summary>
    public ReadOnlySpan<byte> GetChallengeBytes() =>
        AsReadOnlySpan().Slice(BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes * UndisclosedMessageCount, BbsProof.ScalarSizeBytes);


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.ZkProof)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}
