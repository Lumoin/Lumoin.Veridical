using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The HVZK-WHIR proof wire codec. Like the plain
/// <see cref="WhirProofSerialization"/>, the layout carries no length
/// prefixes: every section size is a pure function of the
/// <see cref="WhirZkParameters"/> and the digest size, which both endpoints
/// derive independently, so a proof of a given shape has exactly one accepted
/// byte length. Sections in order: the sumcheck mask oracle roots, the mask
/// totals <c>μ̃</c>, the compressed masked wire polynomials, the folded-oracle
/// roots, the code-switch mask roots, the private out-of-domain replies, per
/// oracle the shift or source query openings, the base case's fresh main
/// root, blind roots and masked claim <c>μ_g</c>, the blinded reveals — the
/// source message, the source randomness and the flat per-group member
/// reveals — the fresh main openings, and per mask group its carried and
/// fresh spot-check openings.
/// </summary>
/// <remarks>
/// <see cref="FromBytes"/> is the reader funnel: every scalar-valued section
/// — mask totals, wire coefficients, out-of-domain replies, the masked claim,
/// the blinded reveals and every opening block — rejects a non-canonical
/// encoding at deserialization, because those bytes are absorbed into the
/// transcript or hashed into leaf digests verbatim and a second byte spelling
/// of the same field element would otherwise be a second accepted proof
/// encoding. Root and path bytes are hash digests and carry no canonical form
/// beyond their length. The mask totals sit directly after the mask roots so
/// each batch's total lands at a fixed early offset —
/// <see cref="ComputeMaskTotalOffset"/> is the seam the transcript simulator
/// patches through.
/// </remarks>
public static class ZkWhirProofSerialization
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// The serialized byte length of an HVZK-WHIR proof of the parameters'
    /// shape at the given digest size.
    /// </summary>
    /// <param name="parameters">The zero-knowledge parameter extension sizing every section.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes, in <c>[1, 64]</c>.</param>
    /// <returns>The exact serialized length in bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="parameters"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="digestSizeBytes"/> is out of range.</exception>
    /// <exception cref="ArgumentException">When the total length overflows the addressable range.</exception>
    public static int ComputeLength(WhirZkParameters parameters, int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSizeBytes, WellKnownMerkleHashParameters.MaximumDigestSizeBytes);

        WhirParameterSchedule schedule = parameters.Schedule;
        int iterationCount = schedule.IterationCount;
        int foldingParameter = schedule.FoldingParameter;
        int wireCoefficientCount = Math.Max(parameters.MaskMessageLength - 1, 2);
        List<(WhirMaskCodeShape Shape, int Width)> groupLayout = ZkWhirIoppVerifier.DeriveGroupLayout(parameters);

        //Widened before the shift-and-scale: a schedule is derivable up to
        //the field's two-adicity, beyond the byte-addressable range, so no
        //section term may wrap before the total check rejects the shape.
        long blockBytes = (1L << foldingParameter) * ScalarSize;

        long total = (long)iterationCount * digestSizeBytes;
        total += (long)iterationCount * ScalarSize;
        total += (long)iterationCount * foldingParameter * wireCoefficientCount * ScalarSize;
        total += (long)(iterationCount - 1) * digestSizeBytes * 2;
        total += (long)(iterationCount - 1) * ScalarSize;
        for(int oracle = 0; oracle < iterationCount; oracle++)
        {
            int pathDepth = schedule.Rounds[oracle].DomainSizeLog2 - foldingParameter;
            total += schedule.Rounds[oracle].QueryCount * (blockBytes + ((long)pathDepth * digestSizeBytes));
        }

        total += digestSizeBytes;
        total += (long)groupLayout.Count * digestSizeBytes;
        total += ScalarSize;

        int lastRandomnessCount = parameters.OracleRandomnessCounts[iterationCount - 1];
        total += ((1L << schedule.FinalVariableCount) + lastRandomnessCount) * ScalarSize;
        foreach((WhirMaskCodeShape shape, int width) in groupLayout)
        {
            total += (long)width * (shape.MessageLength + shape.RandomnessLength) * ScalarSize;
        }

        WhirRoundParameters last = schedule.Rounds[iterationCount - 1];
        int freshPathDepth = last.DomainSizeLog2 - foldingParameter;
        total += last.QueryCount * (ScalarSize + ((long)freshPathDepth * digestSizeBytes));
        foreach((WhirMaskCodeShape shape, int width) in groupLayout)
        {
            long rowBytes = (long)BitOperations.RoundUpToPowerOf2((uint)width) * ScalarSize;
            total += 2L * parameters.MaskQueryCount * (rowBytes + ((long)shape.DomainSizeLog2 * digestSizeBytes));
        }

        if(total > int.MaxValue)
        {
            throw new ArgumentException(
                $"The parameters' proof shape serializes to {total} bytes, above the addressable maximum.",
                nameof(parameters));
        }

        return (int)total;
    }


    /// <summary>
    /// The byte offset of one batch's mask total <c>μ̃</c> inside the wire
    /// layout: the seam a transcript simulator patches through, without any
    /// other layout knowledge.
    /// </summary>
    /// <param name="parameters">The zero-knowledge parameter extension.</param>
    /// <param name="batchIndex">The batch index in <c>[0, M)</c>.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes, in <c>[1, 64]</c>.</param>
    /// <returns>The mask total's byte offset.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="parameters"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When an index or the digest size is out of range.</exception>
    public static int ComputeMaskTotalOffset(
        WhirZkParameters parameters,
        int batchIndex,
        int digestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentOutOfRangeException.ThrowIfNegative(batchIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(batchIndex, parameters.Schedule.IterationCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(digestSizeBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digestSizeBytes, WellKnownMerkleHashParameters.MaximumDigestSizeBytes);

        return (parameters.Schedule.IterationCount * digestSizeBytes) + (batchIndex * ScalarSize);
    }


    /// <summary>
    /// Serializes a proof into a pool-rented buffer in the wire layout.
    /// </summary>
    /// <param name="proof">The proof to serialize.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes; every root and path in the proof must carry it.</param>
    /// <param name="pool">The pool to rent the output buffer from.</param>
    /// <returns>The rented buffer and the exact serialized length; the caller owns the buffer.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a proof part does not match the parameters' shape or the digest size.</exception>
    public static (IMemoryOwner<byte> Owner, int Length) ToBytes(
        ZkWhirIoppProof proof,
        int digestSizeBytes,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(pool);

        WhirZkParameters parameters = proof.Parameters;
        WhirParameterSchedule schedule = parameters.Schedule;
        int length = ComputeLength(parameters, digestSizeBytes);
        int iterationCount = schedule.IterationCount;
        int foldingParameter = schedule.FoldingParameter;
        int wireCoefficientCount = Math.Max(parameters.MaskMessageLength - 1, 2);
        int blockBytes = (1 << foldingParameter) * ScalarSize;
        List<(WhirMaskCodeShape Shape, int Width)> groupLayout = ZkWhirIoppVerifier.DeriveGroupLayout(parameters);

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            Span<byte> output = owner.Memory.Span[..length];
            int offset = 0;

            foreach(MerkleRoot root in proof.SumcheckMaskRoots)
            {
                WriteRoot(root, digestSizeBytes, "sumcheck mask root", output, ref offset);
            }

            foreach(Scalar total in proof.MaskTotals)
            {
                total.AsReadOnlySpan().CopyTo(output.Slice(offset, ScalarSize));
                offset += ScalarSize;
            }

            foreach(CompressedRoundPolynomial polynomial in proof.BatchWirePolynomials)
            {
                WhirProofSerialization.ThrowIfLengthMismatch(polynomial.Degree, wireCoefficientCount, "masked wire degree");
                for(int slot = 0; slot < wireCoefficientCount; slot++)
                {
                    polynomial.GetStoredCoefficientBytes(slot).CopyTo(output.Slice(offset, ScalarSize));
                    offset += ScalarSize;
                }
            }

            foreach(MerkleRoot root in proof.OracleRoots)
            {
                WriteRoot(root, digestSizeBytes, "oracle root", output, ref offset);
            }

            foreach(MerkleRoot root in proof.CodeSwitchMaskRoots)
            {
                WriteRoot(root, digestSizeBytes, "code-switch mask root", output, ref offset);
            }

            foreach(Scalar reply in proof.PrivateOutOfDomainReplies)
            {
                reply.AsReadOnlySpan().CopyTo(output.Slice(offset, ScalarSize));
                offset += ScalarSize;
            }

            for(int oracle = 0; oracle < iterationCount; oracle++)
            {
                int pathBytes = (schedule.Rounds[oracle].DomainSizeLog2 - foldingParameter) * digestSizeBytes;
                foreach(WhirQueryOpening opening in proof.OpeningsForOracle(oracle))
                {
                    WriteOpening(opening, blockBytes, pathBytes, output, ref offset);
                }
            }

            WriteRoot(proof.BaseCaseFreshRoot, digestSizeBytes, "fresh main root", output, ref offset);
            foreach(MerkleRoot root in proof.BaseCaseMaskRoots)
            {
                WriteRoot(root, digestSizeBytes, "fresh blind root", output, ref offset);
            }

            proof.BaseCaseMaskedClaim.AsReadOnlySpan().CopyTo(output.Slice(offset, ScalarSize));
            offset += ScalarSize;

            ReadOnlySpan<byte> sourceMessage = proof.BlindedSourceMessage;
            WhirProofSerialization.ThrowIfLengthMismatch(sourceMessage.Length, (1 << schedule.FinalVariableCount) * ScalarSize, "blinded source message");
            sourceMessage.CopyTo(output.Slice(offset, sourceMessage.Length));
            offset += sourceMessage.Length;

            ReadOnlySpan<byte> sourceRandomness = proof.BlindedSourceRandomness;
            WhirProofSerialization.ThrowIfLengthMismatch(
                sourceRandomness.Length,
                parameters.OracleRandomnessCounts[iterationCount - 1] * ScalarSize,
                "blinded source randomness");
            sourceRandomness.CopyTo(output.Slice(offset, sourceRandomness.Length));
            offset += sourceRandomness.Length;

            ReadOnlySpan<byte> maskReveals = proof.BlindedMaskReveals;
            int expectedRevealBytes = 0;
            foreach((WhirMaskCodeShape shape, int width) in groupLayout)
            {
                expectedRevealBytes += width * (shape.MessageLength + shape.RandomnessLength) * ScalarSize;
            }

            WhirProofSerialization.ThrowIfLengthMismatch(maskReveals.Length, expectedRevealBytes, "blinded mask reveals");
            maskReveals.CopyTo(output.Slice(offset, maskReveals.Length));
            offset += maskReveals.Length;

            WhirRoundParameters last = schedule.Rounds[iterationCount - 1];
            int freshPathBytes = (last.DomainSizeLog2 - foldingParameter) * digestSizeBytes;
            foreach(WhirQueryOpening opening in proof.BaseCaseFreshOpenings)
            {
                WriteOpening(opening, ScalarSize, freshPathBytes, output, ref offset);
            }

            for(int group = 0; group < groupLayout.Count; group++)
            {
                (WhirMaskCodeShape shape, int width) = groupLayout[group];
                int rowBytes = (int)BitOperations.RoundUpToPowerOf2((uint)width) * ScalarSize;
                int groupPathBytes = shape.DomainSizeLog2 * digestSizeBytes;
                (IReadOnlyList<WhirQueryOpening> carried, IReadOnlyList<WhirQueryOpening> fresh) = proof.OpeningsForMaskGroup(group);
                foreach(WhirQueryOpening opening in carried)
                {
                    WriteOpening(opening, rowBytes, groupPathBytes, output, ref offset);
                }

                foreach(WhirQueryOpening opening in fresh)
                {
                    WriteOpening(opening, rowBytes, groupPathBytes, output, ref offset);
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
    /// parameter-derived length and the canonicity of every scalar-valued
    /// section at this reader funnel.
    /// </summary>
    /// <param name="bytes">The serialized proof.</param>
    /// <param name="parameters">The zero-knowledge parameter extension sizing every section, derived independently by this endpoint.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <param name="pool">The pool to rent the proof's buffers from.</param>
    /// <returns>The proof; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the length does not match the parameters' shape or a scalar section is non-canonical.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "Every part transfers ownership to the returned proof; on a failed parse the assembled-flag finally block disposes every part built so far.")]
    public static ZkWhirIoppProof FromBytes(
        ReadOnlySpan<byte> bytes,
        WhirZkParameters parameters,
        int digestSizeBytes,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(pool);

        int expectedLength = ComputeLength(parameters, digestSizeBytes);
        if(bytes.Length != expectedLength)
        {
            throw new ArgumentException(
                $"An HVZK-WHIR proof of this parameters' shape must be {expectedLength} bytes at digest size {digestSizeBytes}; received {bytes.Length}.",
                nameof(bytes));
        }

        WhirParameterSchedule schedule = parameters.Schedule;
        int iterationCount = schedule.IterationCount;
        int foldingParameter = schedule.FoldingParameter;
        int wireCoefficientCount = Math.Max(parameters.MaskMessageLength - 1, 2);
        int blockBytes = (1 << foldingParameter) * ScalarSize;
        CurveParameterSet curve = schedule.Curve;
        List<(WhirMaskCodeShape Shape, int Width)> groupLayout = ZkWhirIoppVerifier.DeriveGroupLayout(parameters);

        var sumcheckMaskRoots = new MerkleRoot[iterationCount];
        var maskTotals = new Scalar[iterationCount];
        var batchWirePolynomials = new CompressedRoundPolynomial[iterationCount * foldingParameter];
        var oracleRoots = new MerkleRoot[iterationCount - 1];
        var codeSwitchMaskRoots = new MerkleRoot[iterationCount - 1];
        var privateOutOfDomainReplies = new Scalar[iterationCount - 1];
        var openings = new WhirQueryOpening[iterationCount][];
        MerkleRoot? baseCaseFreshRoot = null;
        var baseCaseMaskRoots = new MerkleRoot[groupLayout.Count];
        Scalar? baseCaseMaskedClaim = null;
        WhirQueryOpening[]? baseCaseFreshOpenings = null;
        var baseCaseCarriedMaskOpenings = new WhirQueryOpening[groupLayout.Count][];
        var baseCaseFreshMaskOpenings = new WhirQueryOpening[groupLayout.Count][];
        IMemoryOwner<byte>? revealsOwner = null;
        bool assembled = false;

        try
        {
            int offset = 0;

            for(int batch = 0; batch < iterationCount; batch++)
            {
                sumcheckMaskRoots[batch] = MerkleRoot.FromBytes(bytes.Slice(offset, digestSizeBytes), pool);
                offset += digestSizeBytes;
            }

            for(int batch = 0; batch < iterationCount; batch++)
            {
                maskTotals[batch] = WhirProofSerialization.ReadCanonicalScalar(bytes.Slice(offset, ScalarSize), curve, pool, "mask total");
                offset += ScalarSize;
            }

            //FromCompressedBytes enforces the coefficients' canonicity.
            for(int index = 0; index < batchWirePolynomials.Length; index++)
            {
                batchWirePolynomials[index] = CompressedRoundPolynomial.FromCompressedBytes(
                    bytes.Slice(offset, wireCoefficientCount * ScalarSize),
                    wireCoefficientCount,
                    curve,
                    pool);
                offset += wireCoefficientCount * ScalarSize;
            }

            for(int oracle = 1; oracle < iterationCount; oracle++)
            {
                oracleRoots[oracle - 1] = MerkleRoot.FromBytes(bytes.Slice(offset, digestSizeBytes), pool);
                offset += digestSizeBytes;
            }

            for(int oracle = 1; oracle < iterationCount; oracle++)
            {
                codeSwitchMaskRoots[oracle - 1] = MerkleRoot.FromBytes(bytes.Slice(offset, digestSizeBytes), pool);
                offset += digestSizeBytes;
            }

            for(int index = 0; index < privateOutOfDomainReplies.Length; index++)
            {
                privateOutOfDomainReplies[index] = WhirProofSerialization.ReadCanonicalScalar(bytes.Slice(offset, ScalarSize), curve, pool, "private out-of-domain reply");
                offset += ScalarSize;
            }

            for(int oracle = 0; oracle < iterationCount; oracle++)
            {
                int queryCount = schedule.Rounds[oracle].QueryCount;
                int pathBytes = (schedule.Rounds[oracle].DomainSizeLog2 - foldingParameter) * digestSizeBytes;
                var oracleOpenings = new WhirQueryOpening[queryCount];
                openings[oracle] = oracleOpenings;
                for(int query = 0; query < queryCount; query++)
                {
                    oracleOpenings[query] = WhirProofSerialization.ReadOpening(bytes, ref offset, blockBytes, pathBytes, digestSizeBytes, curve, pool);
                }
            }

            baseCaseFreshRoot = MerkleRoot.FromBytes(bytes.Slice(offset, digestSizeBytes), pool);
            offset += digestSizeBytes;
            for(int group = 0; group < groupLayout.Count; group++)
            {
                baseCaseMaskRoots[group] = MerkleRoot.FromBytes(bytes.Slice(offset, digestSizeBytes), pool);
                offset += digestSizeBytes;
            }

            baseCaseMaskedClaim = WhirProofSerialization.ReadCanonicalScalar(bytes.Slice(offset, ScalarSize), curve, pool, "masked claim");
            offset += ScalarSize;

            int sourceMessageBytes = (1 << schedule.FinalVariableCount) * ScalarSize;
            int sourceRandomnessBytes = parameters.OracleRandomnessCounts[iterationCount - 1] * ScalarSize;
            int maskRevealBytes = 0;
            foreach((WhirMaskCodeShape shape, int width) in groupLayout)
            {
                maskRevealBytes += width * (shape.MessageLength + shape.RandomnessLength) * ScalarSize;
            }

            int revealBytes = sourceMessageBytes + sourceRandomnessBytes + maskRevealBytes;
            WhirProofSerialization.ThrowIfNotCanonicalScalars(bytes.Slice(offset, sourceMessageBytes), curve, "blinded source message");
            WhirProofSerialization.ThrowIfNotCanonicalScalars(bytes.Slice(offset + sourceMessageBytes, sourceRandomnessBytes), curve, "blinded source randomness");
            WhirProofSerialization.ThrowIfNotCanonicalScalars(bytes.Slice(offset + sourceMessageBytes + sourceRandomnessBytes, maskRevealBytes), curve, "blinded mask reveal");
            revealsOwner = pool.Rent(revealBytes);
            bytes.Slice(offset, revealBytes).CopyTo(revealsOwner.Memory.Span[..revealBytes]);
            offset += revealBytes;

            WhirRoundParameters last = schedule.Rounds[iterationCount - 1];
            int freshPathBytes = (last.DomainSizeLog2 - foldingParameter) * digestSizeBytes;
            baseCaseFreshOpenings = new WhirQueryOpening[last.QueryCount];
            for(int query = 0; query < baseCaseFreshOpenings.Length; query++)
            {
                baseCaseFreshOpenings[query] = WhirProofSerialization.ReadOpening(bytes, ref offset, ScalarSize, freshPathBytes, digestSizeBytes, curve, pool);
            }

            for(int group = 0; group < groupLayout.Count; group++)
            {
                (WhirMaskCodeShape shape, int width) = groupLayout[group];
                int rowBytes = (int)BitOperations.RoundUpToPowerOf2((uint)width) * ScalarSize;
                int groupPathBytes = shape.DomainSizeLog2 * digestSizeBytes;
                var carried = new WhirQueryOpening[parameters.MaskQueryCount];
                baseCaseCarriedMaskOpenings[group] = carried;
                for(int query = 0; query < carried.Length; query++)
                {
                    carried[query] = WhirProofSerialization.ReadOpening(bytes, ref offset, rowBytes, groupPathBytes, digestSizeBytes, curve, pool);
                }

                var fresh = new WhirQueryOpening[parameters.MaskQueryCount];
                baseCaseFreshMaskOpenings[group] = fresh;
                for(int query = 0; query < fresh.Length; query++)
                {
                    fresh[query] = WhirProofSerialization.ReadOpening(bytes, ref offset, rowBytes, groupPathBytes, digestSizeBytes, curve, pool);
                }
            }

            var proof = new ZkWhirIoppProof(
                parameters,
                batchWirePolynomials,
                sumcheckMaskRoots,
                maskTotals,
                oracleRoots,
                codeSwitchMaskRoots,
                privateOutOfDomainReplies,
                openings,
                baseCaseFreshRoot,
                baseCaseMaskRoots,
                baseCaseMaskedClaim,
                baseCaseFreshOpenings,
                baseCaseCarriedMaskOpenings,
                baseCaseFreshMaskOpenings,
                revealsOwner,
                sourceMessageBytes,
                sourceRandomnessBytes,
                maskRevealBytes);
            assembled = true;

            return proof;
        }
        finally
        {
            if(!assembled)
            {
                WhirProofSerialization.DisposeAll(sumcheckMaskRoots);
                WhirProofSerialization.DisposeAll(maskTotals);
                WhirProofSerialization.DisposeAll(batchWirePolynomials);
                WhirProofSerialization.DisposeAll(oracleRoots);
                WhirProofSerialization.DisposeAll(codeSwitchMaskRoots);
                WhirProofSerialization.DisposeAll(privateOutOfDomainReplies);
                DisposeAllNested(openings);
                baseCaseFreshRoot?.Dispose();
                WhirProofSerialization.DisposeAll(baseCaseMaskRoots);
                baseCaseMaskedClaim?.Dispose();
                if(baseCaseFreshOpenings is not null)
                {
                    WhirProofSerialization.DisposeAll(baseCaseFreshOpenings);
                }

                DisposeAllNested(baseCaseCarriedMaskOpenings);
                DisposeAllNested(baseCaseFreshMaskOpenings);
                revealsOwner?.Dispose();
            }
        }
    }


    /// <summary>
    /// Writes a root's digest bytes, enforcing the digest size, advancing the
    /// offset.
    /// </summary>
    /// <param name="root">The root to write.</param>
    /// <param name="digestSizeBytes">The Merkle digest size in bytes.</param>
    /// <param name="partName">The part name for the failure message.</param>
    /// <param name="output">The output buffer.</param>
    /// <param name="offset">The write cursor, advanced past the digest.</param>
    private static void WriteRoot(MerkleRoot root, int digestSizeBytes, string partName, Span<byte> output, ref int offset)
    {
        ReadOnlySpan<byte> digest = root.AsReadOnlySpan();
        WhirProofSerialization.ThrowIfLengthMismatch(digest.Length, digestSizeBytes, partName);
        digest.CopyTo(output.Slice(offset, digestSizeBytes));
        offset += digestSizeBytes;
    }


    /// <summary>
    /// Writes one query opening — its value block and its authentication
    /// path — enforcing both section lengths, advancing the offset.
    /// </summary>
    /// <param name="opening">The opening to write.</param>
    /// <param name="blockBytes">The value block's byte length.</param>
    /// <param name="pathBytes">The authentication path's byte length.</param>
    /// <param name="output">The output buffer.</param>
    /// <param name="offset">The write cursor, advanced past the opening.</param>
    private static void WriteOpening(WhirQueryOpening opening, int blockBytes, int pathBytes, Span<byte> output, ref int offset)
    {
        WhirProofSerialization.ThrowIfLengthMismatch(opening.BlockValues.Length, blockBytes, "opening block");
        opening.BlockValues.Span.CopyTo(output.Slice(offset, blockBytes));
        offset += blockBytes;

        ReadOnlySpan<byte> path = opening.Path.AsReadOnlySpan();
        WhirProofSerialization.ThrowIfLengthMismatch(path.Length, pathBytes, "authentication path");
        path.CopyTo(output.Slice(offset, pathBytes));
        offset += pathBytes;
    }


    /// <summary>
    /// Disposes every entry of every non-null inner array of a partially
    /// assembled nested part array.
    /// </summary>
    /// <param name="items">The nested part array.</param>
    private static void DisposeAllNested(WhirQueryOpening[]?[] items)
    {
        foreach(WhirQueryOpening[]? inner in items)
        {
            if(inner is not null)
            {
                WhirProofSerialization.DisposeAll(inner);
            }
        }
    }
}
