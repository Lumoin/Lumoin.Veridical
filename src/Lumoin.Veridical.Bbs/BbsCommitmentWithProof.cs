using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A blind-BBS commitment-with-proof: the prover's Pedersen commitment
/// <c>C</c> to its blinding factor and any prover-committed messages,
/// bundled with a Schnorr proof of knowledge of the opening — the
/// variable-length byte composition <c>(C, s^, m^_1, ..., m^_M,
/// challenge)</c> per IETF <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>
/// Section 5.4.1 (<c>commitment_with_proof_to_octets</c>). Pool-rented
/// buffer, runtime-tagged with the Blind BBS Interface identifier and the
/// zero-knowledge-proof algebraic role.
/// </summary>
/// <remarks>
/// <para>
/// The byte length is fixed once the number of committed messages is
/// known: <c>48 (C) + 32 * (M + 2)</c> (the <c>+2</c> covers the response
/// <c>s^</c> for the blinding factor and the Fiat-Shamir <c>challenge</c>).
/// Zero committed messages gives the minimum 112-byte encoding — the
/// shape produced by <c>Commit</c> when the prover discloses no messages
/// of its own to the signer.
/// </para>
/// <para>
/// The committed-message count is recovered from the byte length rather
/// than stored separately, exactly as the spec's
/// <c>octets_to_commitment_with_proof</c> deserialisation does (Section
/// 5.4.2): <c>j</c> scalars follow <c>C</c>, of which the first is
/// <c>s^</c>, the last is <c>challenge</c>, and the <c>j - 2</c> in
/// between are <c>m^_1, ..., m^_M</c>.
/// </para>
/// </remarks>
public sealed class BbsCommitmentWithProof: SensitiveMemory
{
    /// <summary>The canonical byte length of the G1 commitment component <c>C</c>.</summary>
    public const int CSizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>The canonical byte length of each scalar slot.</summary>
    public const int ScalarSizeBytes = WellKnownCurves.Bls12Curve381ScalarSizeBytes;


    /// <summary>The byte offset of the G1 commitment component <c>C</c>.</summary>
    public const int COffset = 0;

    /// <summary>The byte offset of the response scalar <c>s^</c> (for the blinding factor <c>secret_prover_blind</c>).</summary>
    public const int SHatOffset = COffset + CSizeBytes;

    /// <summary>The byte offset of the first committed-message response scalar <c>m^_1</c> (if any).</summary>
    public const int MessageHatsOffset = SHatOffset + ScalarSizeBytes;


    /// <summary>The byte length of a commitment-with-proof over zero committed messages (<c>C</c> + <c>s^</c> + <c>challenge</c>).</summary>
    public const int MinimumSizeBytes = CSizeBytes + 2 * ScalarSizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256Blind);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256Blind);

    private static readonly Tag AlgebraicTagSha256Pseudonym = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256Pseudonym);

    private static readonly Tag AlgebraicTagShake256Pseudonym = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256Pseudonym);


    /// <summary>The extension Interface (Blind BBS or per-verifier-pseudonym) this commitment-with-proof was produced under (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    /// <summary>
    /// Returns the shared algebraic-identity tag every blind-BBS
    /// commitment-with-proof under <paramref name="ciphersuite"/> carries:
    /// zero-knowledge-proof role, BLS12-381 curve, the extension
    /// Interface. The per-verifier-pseudonym Interface commits through the
    /// same <c>CoreCommit</c> machinery (its <c>CommitWithNym</c> output IS
    /// a commitment-with-proof, only under the pseudonym api_id and with
    /// the prover's nym scalars occupying the tail slots), so both
    /// extension Interface families are valid here — but never the core
    /// one, which has no commitment operation.
    /// </summary>
    /// <param name="ciphersuite">One of <see cref="BbsCiphersuite.Bls12Curve381Sha256Blind"/>, <see cref="BbsCiphersuite.Bls12Curve381Shake256Blind"/>, <see cref="BbsCiphersuite.Bls12Curve381Sha256Pseudonym"/>, or <see cref="BbsCiphersuite.Bls12Curve381Shake256Pseudonym"/>.</param>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not one of the four extension Interface values.</exception>
    public static Tag GetAlgebraicTag(BbsCiphersuite ciphersuite)
    {
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256Blind)
        {
            return AlgebraicTagSha256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256Blind)
        {
            return AlgebraicTagShake256;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Sha256Pseudonym)
        {
            return AlgebraicTagSha256Pseudonym;
        }
        if(ciphersuite == BbsCiphersuite.Bls12Curve381Shake256Pseudonym)
        {
            return AlgebraicTagShake256Pseudonym;
        }
        throw new ArgumentException($"Unknown blind-capable BBS Interface ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }


    /// <summary>The number of prover-committed messages — recovered from the byte length.</summary>
    public int CommittedMessageCount { get; }


    internal BbsCommitmentWithProof(IMemoryOwner<byte> owner, int committedMessageCount, Tag tag)
        : base(owner, tag)
    {
        CommittedMessageCount = committedMessageCount;
    }


    /// <summary>
    /// Returns the byte length of a commitment-with-proof over
    /// <paramref name="committedMessageCount"/> committed messages.
    /// </summary>
    /// <param name="committedMessageCount">Non-negative integer.</param>
    /// <returns><c>112 + 32 * committedMessageCount</c>.</returns>
    public static int ComputeSizeBytes(int committedMessageCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(committedMessageCount);
        return MinimumSizeBytes + ScalarSizeBytes * committedMessageCount;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and
    /// returns a commitment-with-proof wrapping it. The committed-message
    /// count is recovered from the byte length per the spec's
    /// <c>octets_to_commitment_with_proof</c> deserialisation.
    /// </summary>
    /// <param name="canonicalBytes">At least <see cref="MinimumSizeBytes"/> bytes; the difference from the minimum must be a multiple of <see cref="ScalarSizeBytes"/>.</param>
    /// <param name="ciphersuite">The Blind BBS Interface ciphersuite.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A commitment-with-proof wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> is shorter than <see cref="MinimumSizeBytes"/>, its length above the minimum is not a multiple of <see cref="ScalarSizeBytes"/>, or any scalar component is zero or not below the scalar field order.</exception>
    public static BbsCommitmentWithProof FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(canonicalBytes.Length < MinimumSizeBytes)
        {
            throw new ArgumentException(
                $"BBS+ commitment-with-proof must be at least {MinimumSizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }
        int extra = canonicalBytes.Length - MinimumSizeBytes;
        if(extra % ScalarSizeBytes != 0)
        {
            throw new ArgumentException(
                $"BBS+ commitment-with-proof length above the minimum ({extra} bytes) must be a multiple of the scalar length ({ScalarSizeBytes}).",
                nameof(canonicalBytes));
        }
        int committedMessageCount = extra / ScalarSizeBytes;

        //The spec's octets_to_commitment_with_proof: every scalar slot after C
        //(s^, the m^_i responses, and the challenge) must be in [1, r-1]. C's
        //point geometry (on-curve, non-identity, prime-order subgroup) is
        //validated at the operation surfaces before any MSM, matching the
        //house pattern already established for BbsSignature's A and
        //BbsProof's Abar/Bbar/D.
        for(int offset = SHatOffset; offset < canonicalBytes.Length; offset += ScalarSizeBytes)
        {
            ReadOnlySpan<byte> scalar = canonicalBytes.Slice(offset, ScalarSizeBytes);
            if(!WellKnownCurves.IsCanonicalScalar(scalar, CurveParameterSet.Bls12Curve381) || scalar.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    $"BBS+ commitment-with-proof scalar at byte offset {offset} must be in [1, r-1]; received zero or a value at or above the scalar field order.",
                    nameof(canonicalBytes));
            }
        }

        IMemoryOwner<byte> owner = pool.Rent(canonicalBytes.Length);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsCommitmentWithProof(owner, committedMessageCount, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the G1 commitment component <c>C</c>.</summary>
    public ReadOnlySpan<byte> GetCBytes() => AsReadOnlySpan().Slice(COffset, CSizeBytes);

    /// <summary>Returns the canonical bytes of the response scalar <c>s^</c>.</summary>
    public ReadOnlySpan<byte> GetSHatBytes() => AsReadOnlySpan().Slice(SHatOffset, ScalarSizeBytes);

    /// <summary>Returns the canonical bytes of the <paramref name="index"/>-th committed-message response scalar <c>m^_j</c>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public ReadOnlySpan<byte> GetMHatBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, CommittedMessageCount);
        return AsReadOnlySpan().Slice(MessageHatsOffset + ScalarSizeBytes * index, ScalarSizeBytes);
    }

    /// <summary>Returns the canonical bytes of the challenge scalar.</summary>
    public ReadOnlySpan<byte> GetChallengeBytes() =>
        AsReadOnlySpan().Slice(MessageHatsOffset + ScalarSizeBytes * CommittedMessageCount, ScalarSizeBytes);


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.ZkProof)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}
