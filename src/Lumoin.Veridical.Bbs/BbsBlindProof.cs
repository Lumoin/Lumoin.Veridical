using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A blind BBS selective-disclosure proof: the -03 FRAMED wire container
/// that wraps a core-layout proof together with the disclosed-message
/// indexes and any committed-disclosure openings, per IETF
/// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 5.4.3
/// (<c>proof_to_octets</c>) / Section 5.4.4 (<c>octets_to_proof</c>).
/// Pool-rented buffer, runtime-tagged with the Blind BBS Interface
/// identifier and the zero-knowledge-proof algebraic role.
/// </summary>
/// <remarks>
/// <para>
/// Unlike core BBS+ (where the disclosed indexes travel alongside the
/// proof as a separate argument), the -03 blind proof wire format frames
/// four length-prefixed sections back to back:
/// </para>
/// <list type="number">
/// <item><description><c>bbs_proof_len</c> (8 bytes) + the core-layout proof itself (<c>272 + 32 * U</c> bytes, <see cref="BbsProof"/>'s own layout).</description></item>
/// <item><description><c>disclosed_indexes_len</c> (8 bytes, <c>R</c>) + <c>R</c> eight-byte indexes.</description></item>
/// <item><description><c>commits_proof_len</c> (8 bytes, <c>N</c>) + <c>N</c> committed-disclosure commitment points (48 bytes each) + <c>N</c> response scalars (32 bytes each).</description></item>
/// <item><description><c>commits_indexes_len</c> (8 bytes, <c>N'</c>, which must equal <c>N</c>) + <c>N'</c> eight-byte indexes.</description></item>
/// </list>
/// <para>
/// Every length prefix is an 8-byte big-endian integer
/// (<c>int_octet_length = 8</c> per Section 5.4.4 Parameters) that this
/// type additionally requires to fit a non-negative <see cref="int"/> —
/// the .NET surface indexes messages and buffers with <see cref="int"/>
/// everywhere else in this library, so a length that overflows it can
/// never be acted on regardless of what the wire claims.
/// </para>
/// </remarks>
public sealed class BbsBlindProof: SensitiveMemory
{
    /// <summary>The byte width of every length/index field in the frame (<c>int_octet_length</c>).</summary>
    public const int Int64FieldSizeBytes = 8;

    /// <summary>The canonical byte length of a committed-disclosure commitment point <c>C_i</c>.</summary>
    public const int CommittedDisclosurePointSizeBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>The canonical byte length of a committed-disclosure response scalar <c>s^_i</c>.</summary>
    public const int CommittedDisclosureScalarSizeBytes = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>The byte offset of the <c>bbs_proof_len</c> frame field.</summary>
    public const int BbsProofLengthOffset = 0;

    /// <summary>The byte offset the core-layout proof begins at (always fixed: it immediately follows the first length field).</summary>
    public const int CoreProofOffset = BbsProofLengthOffset + Int64FieldSizeBytes;

    /// <summary>The byte length of a blind proof with zero undisclosed messages, zero disclosed indexes, and zero committed disclosures.</summary>
    public const int MinimumSizeBytes = CoreProofOffset + BbsProof.MinimumSizeBytes + Int64FieldSizeBytes + Int64FieldSizeBytes + Int64FieldSizeBytes;


    private static readonly Tag AlgebraicTagSha256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Sha256Blind);

    private static readonly Tag AlgebraicTagShake256 = Tag.Create(AlgebraicRole.ZkProof)
        .With(CurveParameterSet.Bls12Curve381)
        .With(BbsCiphersuite.Bls12Curve381Shake256Blind);


    /// <summary>The Blind BBS Interface this proof was produced under (cached lookup from <see cref="Tag"/>).</summary>
    public BbsCiphersuite Ciphersuite => Tag.Get<BbsCiphersuite>();


    /// <summary>
    /// Returns the shared algebraic-identity tag every blind BBS proof
    /// under <paramref name="ciphersuite"/> carries: zero-knowledge-proof
    /// role, BLS12-381 curve, the Blind BBS Interface.
    /// </summary>
    /// <param name="ciphersuite">Either <see cref="BbsCiphersuite.Bls12Curve381Sha256Blind"/> or <see cref="BbsCiphersuite.Bls12Curve381Shake256Blind"/>.</param>
    /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not one of the two Blind BBS Interface values.</exception>
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
        throw new ArgumentException($"Unknown Blind BBS Interface ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
    }


    /// <summary>The number of undisclosed messages in the wrapped core-layout proof (<c>U</c>, recovered from <c>bbs_proof_len</c>).</summary>
    public int UndisclosedMessageCount { get; }

    /// <summary>The number of disclosed-message indexes framed in the proof (<c>R</c>).</summary>
    public int DisclosedIndexCount { get; }

    /// <summary>The number of committed-disclosure openings framed in the proof (<c>N</c>, equal to the frame's own <c>N'</c> by construction).</summary>
    public int CommittedDisclosureCount { get; }


    internal BbsBlindProof(
        IMemoryOwner<byte> owner,
        int undisclosedMessageCount,
        int disclosedIndexCount,
        int committedDisclosureCount,
        Tag tag)
        : base(owner, tag)
    {
        UndisclosedMessageCount = undisclosedMessageCount;
        DisclosedIndexCount = disclosedIndexCount;
        CommittedDisclosureCount = committedDisclosureCount;
    }


    /// <summary>
    /// Returns the total byte length of a blind proof framing a
    /// <paramref name="undisclosedMessageCount"/>-undisclosed core proof,
    /// <paramref name="disclosedIndexCount"/> disclosed indexes, and
    /// <paramref name="committedDisclosureCount"/> committed-disclosure
    /// openings.
    /// </summary>
    public static int ComputeSizeBytes(int undisclosedMessageCount, int disclosedIndexCount, int committedDisclosureCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(undisclosedMessageCount);
        ArgumentOutOfRangeException.ThrowIfNegative(disclosedIndexCount);
        ArgumentOutOfRangeException.ThrowIfNegative(committedDisclosureCount);

        return CoreProofOffset + BbsProof.ComputeSizeBytes(undisclosedMessageCount)
            + Int64FieldSizeBytes + disclosedIndexCount * Int64FieldSizeBytes
            + Int64FieldSizeBytes + committedDisclosureCount * (CommittedDisclosurePointSizeBytes + CommittedDisclosureScalarSizeBytes)
            + Int64FieldSizeBytes + committedDisclosureCount * Int64FieldSizeBytes;
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer
    /// and returns a blind proof wrapping it, after walking every frame
    /// with exact cumulative-length bounds checks, validating the wrapped
    /// core proof's scalar canonicity exactly as
    /// <see cref="BbsProof.FromCanonical"/> does, validating every
    /// committed-disclosure response scalar the same way, and requiring
    /// both index vectors to be strictly ascending and <c>N' == N</c>.
    /// </summary>
    /// <param name="canonicalBytes">The framed proof octets (see the type remarks for the frame layout).</param>
    /// <param name="ciphersuite">The Blind BBS Interface ciphersuite.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries. The algebraic-identity entries are merged in unconditionally.</param>
    /// <returns>A blind proof wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When any frame is truncated, any length field does not fit a non-negative <see cref="int"/>, <c>N' != N</c>, the trailing bytes do not end exactly at the declared total length, either index vector is not strictly ascending, or any scalar slot (core proof or committed-disclosure response) is zero or not below the scalar field order.</exception>
    public static BbsBlindProof FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BbsCiphersuite ciphersuite,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int cursor = ReadFrameLengthField(canonicalBytes, BbsProofLengthOffset, "bbs_proof_len", out int coreProofSizeBytes);
        int coreProofExtra = coreProofSizeBytes - BbsProof.MinimumSizeBytes;
        if(coreProofSizeBytes < BbsProof.MinimumSizeBytes || coreProofExtra % BbsProof.ScalarSizeBytes != 0)
        {
            throw new ArgumentException(
                $"BBS+ blind proof bbs_proof_len ({coreProofSizeBytes}) is not a valid core BBS+ proof length.",
                nameof(canonicalBytes));
        }
        int undisclosedMessageCount = coreProofExtra / BbsProof.ScalarSizeBytes;

        //Every cumulative end-offset below is computed in long: the counts are
        //attacker-controlled and int products of them wrap, which would let a
        //huge count slip past the truncation guard and only fail later inside
        //a slice. Once a guard passes, the end offset provably fits an int.
        RequireLength(canonicalBytes, (long)cursor + coreProofSizeBytes, "the framed core proof");
        ReadOnlySpan<byte> coreProofBytes = canonicalBytes.Slice(cursor, coreProofSizeBytes);
        cursor += coreProofSizeBytes;

        //Mirrors BbsProof.FromCanonical's own scalar-canonicity loop exactly,
        //applied to the framed core proof's scalar region.
        for(int offset = BbsProof.EHatOffset; offset < coreProofBytes.Length; offset += BbsProof.ScalarSizeBytes)
        {
            ReadOnlySpan<byte> scalar = coreProofBytes.Slice(offset, BbsProof.ScalarSizeBytes);
            if(!WellKnownCurves.IsCanonicalScalar(scalar, CurveParameterSet.Bls12Curve381) || scalar.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    $"BBS+ blind proof's framed core proof scalar at byte offset {offset} must be in [1, r-1]; received zero or a value at or above the scalar field order.",
                    nameof(canonicalBytes));
            }
        }

        cursor = ReadFrameLengthField(canonicalBytes, cursor, "disclosed_indexes_len", out int disclosedIndexCount);
        long disclosedIndexesEnd = cursor + (long)disclosedIndexCount * Int64FieldSizeBytes;
        RequireLength(canonicalBytes, disclosedIndexesEnd, "the disclosed_indexes vector");
        ValidateAscendingIndexVector(canonicalBytes, cursor, disclosedIndexCount, "disclosed_indexes");
        cursor = (int)disclosedIndexesEnd;

        cursor = ReadFrameLengthField(canonicalBytes, cursor, "commits_proof_len", out int committedDisclosureCount);
        long committedDisclosureBlockEnd = cursor + (long)committedDisclosureCount * (CommittedDisclosurePointSizeBytes + CommittedDisclosureScalarSizeBytes);
        RequireLength(canonicalBytes, committedDisclosureBlockEnd, "the commits_proof block");
        int committedDisclosureScalarsOffset = cursor + committedDisclosureCount * CommittedDisclosurePointSizeBytes;
        for(int i = 0; i < committedDisclosureCount; i++)
        {
            ReadOnlySpan<byte> scalar = canonicalBytes.Slice(committedDisclosureScalarsOffset + i * CommittedDisclosureScalarSizeBytes, CommittedDisclosureScalarSizeBytes);
            if(!WellKnownCurves.IsCanonicalScalar(scalar, CurveParameterSet.Bls12Curve381) || scalar.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    $"BBS+ blind proof committed-disclosure response scalar #{i} must be in [1, r-1]; received zero or a value at or above the scalar field order.",
                    nameof(canonicalBytes));
            }
        }
        cursor = (int)committedDisclosureBlockEnd;

        cursor = ReadFrameLengthField(canonicalBytes, cursor, "commits_indexes_len", out int committedDisclosureIndexCount);
        if(committedDisclosureIndexCount != committedDisclosureCount)
        {
            throw new ArgumentException(
                $"BBS+ blind proof commits_indexes_len ({committedDisclosureIndexCount}) must equal commits_proof_len ({committedDisclosureCount}).",
                nameof(canonicalBytes));
        }
        long committedDisclosureIndexesEnd = cursor + (long)committedDisclosureIndexCount * Int64FieldSizeBytes;
        RequireLength(canonicalBytes, committedDisclosureIndexesEnd, "the commits_indexes vector");
        ValidateAscendingIndexVector(canonicalBytes, cursor, committedDisclosureIndexCount, "commits_indexes");
        cursor = (int)committedDisclosureIndexesEnd;

        if(cursor != canonicalBytes.Length)
        {
            throw new ArgumentException(
                $"BBS+ blind proof declares a total length of {cursor} bytes but {canonicalBytes.Length} bytes were supplied.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(canonicalBytes.Length);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null
            ? GetAlgebraicTag(ciphersuite)
            : MergeWithAlgebraicTag(tag, ciphersuite);

        return new BbsBlindProof(owner, undisclosedMessageCount, disclosedIndexCount, committedDisclosureCount, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the wrapped core-layout proof (<c>272 + 32 * UndisclosedMessageCount</c> bytes).</summary>
    public ReadOnlySpan<byte> GetCoreProofBytes() =>
        AsReadOnlySpan().Slice(CoreProofOffset, BbsProof.ComputeSizeBytes(UndisclosedMessageCount));

    /// <summary>Returns the raw 8-byte big-endian encoding of the <paramref name="index"/>-th disclosed-message index.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public ReadOnlySpan<byte> GetDisclosedIndexBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, DisclosedIndexCount);
        return AsReadOnlySpan().Slice(DisclosedIndexesOffset + index * Int64FieldSizeBytes, Int64FieldSizeBytes);
    }

    /// <summary>Returns the <paramref name="index"/>-th disclosed-message index as an <see cref="int"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public int GetDisclosedIndex(int index) => checked((int)BinaryPrimitives.ReadUInt64BigEndian(GetDisclosedIndexBytes(index)));

    /// <summary>Returns the canonical bytes of the <paramref name="index"/>-th committed-disclosure commitment point <c>C_i</c> (48 bytes).</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public ReadOnlySpan<byte> GetCommittedDisclosurePointBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, CommittedDisclosureCount);
        return AsReadOnlySpan().Slice(CommittedDisclosurePointsOffset + index * CommittedDisclosurePointSizeBytes, CommittedDisclosurePointSizeBytes);
    }

    /// <summary>Returns the canonical bytes of the <paramref name="index"/>-th committed-disclosure response scalar <c>s^_i</c> (32 bytes).</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public ReadOnlySpan<byte> GetCommittedDisclosureScalarBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, CommittedDisclosureCount);
        return AsReadOnlySpan().Slice(CommittedDisclosureScalarsOffset + index * CommittedDisclosureScalarSizeBytes, CommittedDisclosureScalarSizeBytes);
    }

    /// <summary>Returns the raw 8-byte big-endian encoding of the <paramref name="index"/>-th committed-disclosure index (from <c>commits_indexes</c>).</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public ReadOnlySpan<byte> GetCommittedDisclosureIndexBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, CommittedDisclosureCount);
        return AsReadOnlySpan().Slice(CommittedDisclosureIndexesOffset + index * Int64FieldSizeBytes, Int64FieldSizeBytes);
    }

    /// <summary>Returns the <paramref name="index"/>-th committed-disclosure index as an <see cref="int"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="index"/> is out of range.</exception>
    public int GetCommittedDisclosureIndex(int index) => checked((int)BinaryPrimitives.ReadUInt64BigEndian(GetCommittedDisclosureIndexBytes(index)));


    private int DisclosedIndexesOffset =>
        CoreProofOffset + BbsProof.ComputeSizeBytes(UndisclosedMessageCount) + Int64FieldSizeBytes;

    private int CommittedDisclosurePointsOffset =>
        DisclosedIndexesOffset + DisclosedIndexCount * Int64FieldSizeBytes + Int64FieldSizeBytes;

    private int CommittedDisclosureScalarsOffset =>
        CommittedDisclosurePointsOffset + CommittedDisclosureCount * CommittedDisclosurePointSizeBytes;

    private int CommittedDisclosureIndexesOffset =>
        CommittedDisclosureScalarsOffset + CommittedDisclosureCount * CommittedDisclosureScalarSizeBytes + Int64FieldSizeBytes;


    /// <summary>
    /// Reads the 8-byte big-endian length/count field at <paramref name="offset"/>,
    /// requiring the buffer to hold at least <see cref="Int64FieldSizeBytes"/>
    /// bytes there and the value to fit a non-negative <see cref="int"/>.
    /// </summary>
    /// <returns>The offset immediately after the field.</returns>
    private static int ReadFrameLengthField(ReadOnlySpan<byte> canonicalBytes, int offset, string fieldName, out int value)
    {
        RequireLength(canonicalBytes, (long)offset + Int64FieldSizeBytes, $"the {fieldName} frame field");

        ulong raw = BinaryPrimitives.ReadUInt64BigEndian(canonicalBytes.Slice(offset, Int64FieldSizeBytes));
        if(raw > int.MaxValue)
        {
            throw new ArgumentException(
                $"BBS+ blind proof {fieldName} ({raw}) does not fit a non-negative 32-bit length.",
                nameof(canonicalBytes));
        }
        value = (int)raw;

        return offset + Int64FieldSizeBytes;
    }


    private static void RequireLength(ReadOnlySpan<byte> canonicalBytes, long requiredLength, string what)
    {
        if(canonicalBytes.Length < requiredLength)
        {
            throw new ArgumentException(
                $"BBS+ blind proof is truncated: {what} requires at least {requiredLength} total bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }
    }


    /// <summary>
    /// Validates that the <paramref name="count"/> eight-byte big-endian
    /// indexes starting at <paramref name="offset"/> each fit a
    /// non-negative <see cref="int"/> and are strictly ascending.
    /// </summary>
    private static void ValidateAscendingIndexVector(ReadOnlySpan<byte> canonicalBytes, int offset, int count, string vectorName)
    {
        long previousIndex = -1;
        for(int i = 0; i < count; i++)
        {
            ulong raw = BinaryPrimitives.ReadUInt64BigEndian(canonicalBytes.Slice(offset + i * Int64FieldSizeBytes, Int64FieldSizeBytes));
            if(raw > int.MaxValue)
            {
                throw new ArgumentException(
                    $"BBS+ blind proof {vectorName}[{i}] ({raw}) does not fit a non-negative 32-bit index.",
                    nameof(canonicalBytes));
            }
            long index = (long)raw;
            if(index <= previousIndex)
            {
                throw new ArgumentException(
                    $"BBS+ blind proof {vectorName} must be strictly ascending; index {index} at position {i} does not exceed the preceding index {previousIndex}.",
                    nameof(canonicalBytes));
            }
            previousIndex = index;
        }
    }


    private static Tag MergeWithAlgebraicTag(Tag tag, BbsCiphersuite ciphersuite)
    {
        return tag.With(AlgebraicRole.ZkProof)
            .With(CurveParameterSet.Bls12Curve381)
            .With(ciphersuite);
    }
}
