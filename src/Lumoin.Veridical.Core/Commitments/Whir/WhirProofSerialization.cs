using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The WHIR IOPP proof wire codec. The layout carries no length prefixes:
/// every section size is a pure function of the
/// <see cref="WhirParameterSchedule"/> and the digest size, which both
/// endpoints derive independently, so a proof of a given shape has exactly
/// one accepted byte length. Sections in order: the folded-oracle Merkle
/// roots, the compressed sumcheck round polynomials, the out-of-domain
/// replies, the cleartext final polynomial, and per oracle the query
/// openings — each a coset value block followed by its authentication path.
/// </summary>
/// <remarks>
/// <see cref="FromBytes"/> is the reader funnel: every scalar-valued section
/// — round polynomial coefficients, out-of-domain replies, final-polynomial
/// coefficients and opening block values — rejects a non-canonical encoding
/// at deserialization, because those bytes are absorbed into the transcript
/// or hashed into leaf digests verbatim and a second byte spelling of the
/// same field element would otherwise be a second accepted proof encoding.
/// Root and path bytes are hash digests and carry no canonical form beyond
/// their length. The schedule's own derivation is the dimension authority
/// for the counts the size arithmetic consumes; a schedule remains derivable
/// up to the field's two-adicity — beyond the byte-addressable range — so
/// the codec computes its block and total terms widened and rejects any
/// shape whose serialization exceeds the addressable maximum, adding only
/// that check and the digest-size cap of its own.
/// </remarks>
public static class WhirProofSerialization
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>
    /// The compressed sumcheck round polynomials carry two stored
    /// coefficients, <c>(c_0, c_2)</c>; the linear term is reconstructed
    /// from the running claim and never travels.
    /// </summary>
    private const int RoundPolynomialDegree = 2;


    /// <summary>
    /// The serialized byte length of a WHIR proof of the schedule's shape at
    /// the given digest size.
    /// </summary>
    /// <param name="schedule">The parameter schedule sizing every section.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes, in <c>[1, 64]</c>.</param>
    /// <returns>The exact serialized length in bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="schedule"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="digestSizeBytes"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When the total length overflows the addressable range.</exception>
    public static int ComputeLength(WhirParameterSchedule schedule, int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSizeBytes, WellKnownMerkleHashParameters.MaximumDigestSizeBytes);

        int iterationCount = schedule.IterationCount;

        //Widened before the shift-and-scale: a schedule is derivable up to
        //the field's two-adicity, beyond the byte-addressable range, so the
        //block term must not wrap before the total check rejects the shape.
        long blockBytes = (1L << schedule.FoldingParameter) * ScalarSize;

        long total = (long)(iterationCount - 1) * digestSizeBytes;
        total += (long)iterationCount * schedule.FoldingParameter * RoundPolynomialDegree * ScalarSize;
        total += (long)(iterationCount - 1) * ScalarSize;
        total += (long)(1 << schedule.FinalVariableCount) * ScalarSize;
        for(int oracle = 0; oracle < iterationCount; oracle++)
        {
            int pathDepth = schedule.Rounds[oracle].DomainSizeLog2 - schedule.FoldingParameter;
            total += schedule.Rounds[oracle].QueryCount * (blockBytes + ((long)pathDepth * digestSizeBytes));
        }

        if(total > int.MaxValue)
        {
            throw new ArgumentException(
                $"The schedule's proof shape serializes to {total} bytes, above the addressable maximum.",
                nameof(schedule));
        }

        return (int)total;
    }


    /// <summary>
    /// Serializes a proof into a pool-rented buffer in the wire layout.
    /// </summary>
    /// <param name="proof">The proof to serialize.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes; every root and path in the proof must carry it.</param>
    /// <param name="pool">The pool to rent the output buffer from.</param>
    /// <returns>The rented buffer and the exact serialized length; the caller owns the buffer.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a proof part does not match the schedule's shape or the digest size.</exception>
    public static (IMemoryOwner<byte> Owner, int Length) ToBytes(
        WhirIoppProof proof,
        int digestSizeBytes,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(pool);

        WhirParameterSchedule schedule = proof.Schedule;
        int length = ComputeLength(schedule, digestSizeBytes);
        int iterationCount = schedule.IterationCount;
        int blockBytes = (1 << schedule.FoldingParameter) * ScalarSize;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            Span<byte> output = owner.Memory.Span[..length];
            int offset = 0;

            for(int oracle = 1; oracle < iterationCount; oracle++)
            {
                ReadOnlySpan<byte> root = proof.OracleRoots[oracle - 1].AsReadOnlySpan();
                ThrowIfLengthMismatch(root.Length, digestSizeBytes, "oracle root");
                root.CopyTo(output.Slice(offset, digestSizeBytes));
                offset += digestSizeBytes;
            }

            foreach(CompressedRoundPolynomial polynomial in proof.RoundPolynomials)
            {
                ThrowIfLengthMismatch(polynomial.Degree, RoundPolynomialDegree, "round polynomial degree");
                for(int slot = 0; slot < RoundPolynomialDegree; slot++)
                {
                    polynomial.GetStoredCoefficientBytes(slot).CopyTo(output.Slice(offset, ScalarSize));
                    offset += ScalarSize;
                }
            }

            foreach(Scalar reply in proof.OutOfDomainReplies)
            {
                reply.AsReadOnlySpan().CopyTo(output.Slice(offset, ScalarSize));
                offset += ScalarSize;
            }

            ReadOnlySpan<byte> finalPolynomial = proof.FinalPolynomial;
            ThrowIfLengthMismatch(finalPolynomial.Length, (1 << schedule.FinalVariableCount) * ScalarSize, "final polynomial");
            finalPolynomial.CopyTo(output.Slice(offset, finalPolynomial.Length));
            offset += finalPolynomial.Length;

            for(int oracle = 0; oracle < iterationCount; oracle++)
            {
                int pathBytes = (schedule.Rounds[oracle].DomainSizeLog2 - schedule.FoldingParameter) * digestSizeBytes;
                foreach(WhirQueryOpening opening in proof.OpeningsForOracle(oracle))
                {
                    ThrowIfLengthMismatch(opening.BlockValues.Length, blockBytes, "opening block");
                    opening.BlockValues.Span.CopyTo(output.Slice(offset, blockBytes));
                    offset += blockBytes;

                    ReadOnlySpan<byte> path = opening.Path.AsReadOnlySpan();
                    ThrowIfLengthMismatch(path.Length, pathBytes, "authentication path");
                    path.CopyTo(output.Slice(offset, pathBytes));
                    offset += pathBytes;
                }
            }

            return (owner, length);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Deserializes a proof from the wire layout, enforcing the exact
    /// schedule-derived length and the canonicity of every scalar-valued
    /// section at this reader funnel.
    /// </summary>
    /// <param name="bytes">The serialized proof.</param>
    /// <param name="schedule">The parameter schedule sizing every section, derived independently by this endpoint.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <param name="pool">The pool to rent the proof's buffers from.</param>
    /// <returns>The proof; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the length does not match the schedule's shape or a scalar section is non-canonical.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Every part transfers ownership to the returned proof; on a failed parse the assembled-flag finally block disposes every part built so far.")]
    public static WhirIoppProof FromBytes(
        ReadOnlySpan<byte> bytes,
        WhirParameterSchedule schedule,
        int digestSizeBytes,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        ArgumentNullException.ThrowIfNull(pool);

        int expectedLength = ComputeLength(schedule, digestSizeBytes);
        if(bytes.Length != expectedLength)
        {
            throw new ArgumentException(
                $"A WHIR proof of this schedule's shape must be {expectedLength} bytes at digest size {digestSizeBytes}; received {bytes.Length}.",
                nameof(bytes));
        }

        int iterationCount = schedule.IterationCount;
        int foldingParameter = schedule.FoldingParameter;
        int blockBytes = (1 << foldingParameter) * ScalarSize;
        int finalBytes = (1 << schedule.FinalVariableCount) * ScalarSize;
        CurveParameterSet curve = schedule.Curve;

        var oracleRoots = new MerkleRoot[iterationCount - 1];
        var roundPolynomials = new CompressedRoundPolynomial[iterationCount * foldingParameter];
        var outOfDomainReplies = new Scalar[iterationCount - 1];
        var openings = new WhirQueryOpening[iterationCount][];
        IMemoryOwner<byte>? finalOwner = null;
        bool assembled = false;

        try
        {
            int offset = 0;

            for(int oracle = 1; oracle < iterationCount; oracle++)
            {
                oracleRoots[oracle - 1] = MerkleRoot.FromBytes(bytes.Slice(offset, digestSizeBytes), pool);
                offset += digestSizeBytes;
            }

            //FromCompressedBytes enforces the coefficients' canonicity.
            for(int index = 0; index < roundPolynomials.Length; index++)
            {
                roundPolynomials[index] = CompressedRoundPolynomial.FromCompressedBytes(
                    bytes.Slice(offset, RoundPolynomialDegree * ScalarSize),
                    RoundPolynomialDegree,
                    curve,
                    pool);
                offset += RoundPolynomialDegree * ScalarSize;
            }

            for(int index = 0; index < outOfDomainReplies.Length; index++)
            {
                outOfDomainReplies[index] = ReadCanonicalScalar(bytes.Slice(offset, ScalarSize), curve, pool, "out-of-domain reply");
                offset += ScalarSize;
            }

            ThrowIfNotCanonicalScalars(bytes.Slice(offset, finalBytes), curve, "final polynomial");
            finalOwner = pool.Rent(finalBytes);
            bytes.Slice(offset, finalBytes).CopyTo(finalOwner.Memory.Span[..finalBytes]);
            offset += finalBytes;

            for(int oracle = 0; oracle < iterationCount; oracle++)
            {
                int queryCount = schedule.Rounds[oracle].QueryCount;
                int pathBytes = (schedule.Rounds[oracle].DomainSizeLog2 - foldingParameter) * digestSizeBytes;
                var oracleOpenings = new WhirQueryOpening[queryCount];
                openings[oracle] = oracleOpenings;
                for(int query = 0; query < queryCount; query++)
                {
                    oracleOpenings[query] = ReadOpening(bytes, ref offset, blockBytes, pathBytes, digestSizeBytes, curve, pool);
                }
            }

            var proof = new WhirIoppProof(
                schedule,
                oracleRoots,
                roundPolynomials,
                outOfDomainReplies,
                finalOwner,
                finalBytes,
                openings);
            assembled = true;

            return proof;
        }
        finally
        {
            if(!assembled)
            {
                DisposeAll(oracleRoots);
                DisposeAll(roundPolynomials);
                DisposeAll(outOfDomainReplies);
                foreach(WhirQueryOpening[]? oracleOpenings in openings)
                {
                    if(oracleOpenings is not null)
                    {
                        DisposeAll(oracleOpenings);
                    }
                }

                finalOwner?.Dispose();
            }
        }
    }


    /// <summary>
    /// Reads one query opening — a canonical coset value block and its
    /// authentication path — advancing the offset.
    /// </summary>
    /// <param name="bytes">The serialized proof.</param>
    /// <param name="offset">The read cursor, advanced past the opening.</param>
    /// <param name="blockBytes">The coset value block's byte length.</param>
    /// <param name="pathBytes">The authentication path's byte length.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool to rent the opening's buffers from.</param>
    /// <returns>The opening; ownership transfers to the caller.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The values and path buffers transfer ownership to the returned opening; the catch block releases them on a failed parse.")]
    internal static WhirQueryOpening ReadOpening(
        ReadOnlySpan<byte> bytes,
        ref int offset,
        int blockBytes,
        int pathBytes,
        int digestSizeBytes,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ThrowIfNotCanonicalScalars(bytes.Slice(offset, blockBytes), curve, "opening block");

        IMemoryOwner<byte> valuesOwner = pool.Rent(blockBytes);
        IMemoryOwner<byte>? pathOwner = null;
        try
        {
            bytes.Slice(offset, blockBytes).CopyTo(valuesOwner.Memory.Span[..blockBytes]);
            offset += blockBytes;

            pathOwner = pool.Rent(pathBytes);
            bytes.Slice(offset, pathBytes).CopyTo(pathOwner.Memory.Span[..pathBytes]);
            offset += pathBytes;

            MerkleAuthenticationPath path = MerkleAuthenticationPath.Create(pathOwner, digestSizeBytes);

            return new WhirQueryOpening(valuesOwner, blockBytes, path);
        }
        catch
        {
            valuesOwner.Dispose();
            pathOwner?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Copies a canonical scalar into a pool-owned <see cref="Scalar"/>,
    /// rejecting a non-canonical encoding.
    /// </summary>
    /// <param name="bytes">The scalar's serialized bytes.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool to rent the scalar's buffer from.</param>
    /// <param name="sectionName">The section name for the rejection message.</param>
    /// <returns>The scalar; ownership transfers to the caller.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned scalar.")]
    internal static Scalar ReadCanonicalScalar(ReadOnlySpan<byte> bytes, CurveParameterSet curve, BaseMemoryPool pool, string sectionName)
    {
        ThrowIfNotCanonicalScalars(bytes, curve, sectionName);

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        bytes.CopyTo(owner.Memory.Span[..ScalarSize]);

        return new Scalar(owner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }


    /// <summary>
    /// Rejects any non-canonical element in a whole-scalar section: these
    /// bytes are absorbed or hashed verbatim, so a non-canonical spelling
    /// would give the same proof a second accepted byte representation.
    /// </summary>
    /// <param name="scalars">The section's bytes, a whole number of elements.</param>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="sectionName">The section name for the rejection message.</param>
    internal static void ThrowIfNotCanonicalScalars(ReadOnlySpan<byte> scalars, CurveParameterSet curve, string sectionName)
    {
        for(int offset = 0; offset < scalars.Length; offset += ScalarSize)
        {
            if(!WellKnownCurves.IsCanonicalScalar(scalars.Slice(offset, ScalarSize), curve))
            {
                throw new ArgumentException(
                    $"A {sectionName} element at byte offset {offset} encodes an integer at or above the scalar field order of {curve}.",
                    nameof(scalars));
            }
        }
    }


    /// <summary>
    /// Fails loudly when a serialized part's figure does not match the
    /// schedule-derived expectation.
    /// </summary>
    /// <param name="actual">The part's actual figure.</param>
    /// <param name="expected">The schedule-derived figure.</param>
    /// <param name="partName">The part name for the failure message.</param>
    internal static void ThrowIfLengthMismatch(int actual, int expected, string partName)
    {
        if(actual != expected)
        {
            throw new ArgumentException($"The proof's {partName} carries {actual} where the schedule requires {expected}.", nameof(actual));
        }
    }


    /// <summary>
    /// Disposes every non-null entry of a partially assembled part array —
    /// the failed-parse cleanup of parts not yet owned by a proof.
    /// </summary>
    /// <param name="items">The part array.</param>
    internal static void DisposeAll<T>(T?[] items) where T: class, IDisposable
    {
        foreach(T? item in items)
        {
            item?.Dispose();
        }
    }
}
