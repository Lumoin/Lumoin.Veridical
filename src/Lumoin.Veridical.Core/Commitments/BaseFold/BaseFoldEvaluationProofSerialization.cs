using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Canonical byte (de)serialization for <see cref="BaseFoldEvaluationProof"/>,
/// the form a <see cref="PolynomialOpening"/> carries on the scheme-agnostic
/// commitment surface. The wire layout is fully determined by the code
/// parameters, the query count, and the digest size — all known to both
/// endpoints — so it carries no length prefixes:
/// </summary>
/// <remarks>
/// <para>
/// Layout (every scalar is 32 bytes, every digest <c>digestSize</c> bytes):
/// </para>
/// <list type="number">
///   <item><description><c>d</c> round polynomials, each the degree-2 compressed pair <c>(c_0, c_2)</c> = 64 bytes, in send order <c>h_d … h_1</c>.</description></item>
///   <item><description><c>d − 1</c> fold roots, each one digest, in commit order <c>π_{d-1} … π_1</c>.</description></item>
///   <item><description>the cleartext base codeword <c>π_0</c>: <c>n_0 = c·k0</c> scalars.</description></item>
///   <item><description>for each query, for each layer step <c>s = 0 … d-1</c> (layer <c>level = d − s</c>): the two pair values (a scalar each) then the two authentication paths (<c>log2(n_level)</c> siblings each).</description></item>
/// </list>
/// <para>
/// Because every field has a known size, a tampered or truncated buffer either
/// fails the total-length guard or reconstructs into a proof that fails
/// verification — the verifier never trusts the bytes blindly.
/// </para>
/// </remarks>
internal static class BaseFoldEvaluationProofSerialization
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The degree-2 round polynomial is stored compressed as (c_0, c_2).
    private const int RoundPolynomialDegree = 2;
    private const int RoundPolynomialBytes = RoundPolynomialDegree * ScalarSize;


    /// <summary>
    /// Serializes <paramref name="proof"/> into a fresh pool-rented buffer under
    /// the given opening <paramref name="mode"/>.
    /// </summary>
    /// <returns>The owner of the serialized bytes and their length; the caller owns disposal.</returns>
    internal static (IMemoryOwner<byte> Owner, int Length) ToBytes(
        BaseFoldEvaluationProof proof,
        int digestSize,
        BaseFoldOpeningMode mode,
        BaseMemoryPool pool)
    {
        FoldableCodeParameters parameters = proof.Parameters;
        int d = parameters.LayerCount;
        int baseUnit = parameters.InverseRate * parameters.BaseDimension;
        bool hiding = mode is BaseFoldOpeningMode.Hiding or BaseFoldOpeningMode.ZeroKnowledge;
        bool zeroKnowledge = mode is BaseFoldOpeningMode.ZeroKnowledge;

        int totalLength = ComputeLength(parameters, proof.QueryCount, digestSize, mode);

        IMemoryOwner<byte> owner = pool.Rent(totalLength);
        Span<byte> buffer = owner.Memory.Span[..totalLength];
        int cursor = 0;

        for(int i = 0; i < d; i++)
        {
            cursor += Write(buffer, cursor, proof.RoundPolynomials[i].AsReadOnlySpan());
        }

        for(int i = 0; i < d - 1; i++)
        {
            cursor += Write(buffer, cursor, proof.FoldRoots[i].AsReadOnlySpan());
        }

        cursor += Write(buffer, cursor, proof.FinalOracle);

        cursor = WriteOpenings(buffer, cursor, proof.Openings, proof.QueryCount, d, hiding);

        //The statistical-ZK mask side (design doc §2 v3): com(C*)'s root, σ,
        //σ_F, then the nested hiding weighted opening at the deterministic
        //mask-commitment shape.
        if(zeroKnowledge)
        {
            BaseFoldMaskOpening maskOpening = proof.Mask ?? throw new ArgumentException(
                "A zero-knowledge BaseFold evaluation proof must carry a mask opening.", nameof(proof));

            cursor += Write(buffer, cursor, maskOpening.CommitmentRoot.AsReadOnlySpan());
            cursor += Write(buffer, cursor, maskOpening.Sigma);
            cursor += Write(buffer, cursor, maskOpening.FillerSum);

            (IMemoryOwner<byte> nestedOwner, int nestedLength) = ToBytes(maskOpening.WeightedOpening, digestSize, BaseFoldOpeningMode.Hiding, pool);
            using(nestedOwner)
            {
                cursor += Write(buffer, cursor, nestedOwner.Memory.Span[..nestedLength]);
            }
        }

        return (owner, totalLength);
    }


    //Writes one side's per-query openings: for each query, each layer step's two
    //pair values, then (when hiding) the two leaf salts, then the two paths.
    private static int WriteOpenings(
        Span<byte> buffer,
        int cursor,
        System.Collections.Generic.IReadOnlyList<System.Collections.Generic.IReadOnlyList<BaseFoldQueryStep>> openings,
        int queryCount,
        int d,
        bool hiding)
    {
        for(int q = 0; q < queryCount; q++)
        {
            System.Collections.Generic.IReadOnlyList<BaseFoldQueryStep> steps = openings[q];
            for(int s = 0; s < d; s++)
            {
                BaseFoldQueryStep step = steps[s];
                cursor += Write(buffer, cursor, step.First);
                cursor += Write(buffer, cursor, step.Second);

                if(hiding)
                {
                    cursor += Write(buffer, cursor, step.FirstSalt);
                    cursor += Write(buffer, cursor, step.SecondSalt);
                }

                cursor += Write(buffer, cursor, step.FirstPath.AsReadOnlySpan());
                cursor += Write(buffer, cursor, step.SecondPath.AsReadOnlySpan());
            }
        }

        return cursor;
    }


    /// <summary>
    /// Reconstructs a <see cref="BaseFoldEvaluationProof"/> from its canonical
    /// bytes. Throws on a length mismatch; the caller (the verify operation)
    /// treats that as a rejection.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "Each reconstructed authentication path transfers ownership to its BaseFoldQueryStep; the steps transfer to the returned proof (or its mask opening) on success, and on the failure path are disposed through the openings/mask cleanup, which disposes their paths. The total-length guard runs before any path is read, so the per-step reads cannot throw mid-step and orphan a path.")]
    internal static BaseFoldEvaluationProof FromBytes(
        ReadOnlySpan<byte> bytes,
        FoldableCodeParameters parameters,
        int queryCount,
        int digestSize,
        BaseFoldOpeningMode mode,
        BaseMemoryPool pool)
    {
        int d = parameters.LayerCount;
        int baseUnit = parameters.InverseRate * parameters.BaseDimension;
        CurveParameterSet curve = parameters.Curve;
        bool hiding = mode is BaseFoldOpeningMode.Hiding or BaseFoldOpeningMode.ZeroKnowledge;
        bool zeroKnowledge = mode is BaseFoldOpeningMode.ZeroKnowledge;

        int expectedLength = ComputeLength(parameters, queryCount, digestSize, mode);
        if(bytes.Length != expectedLength)
        {
            throw new ArgumentException(
                $"BaseFold evaluation proof must be {expectedLength} bytes for d = {d}, queryCount = {queryCount}, digest = {digestSize}, mode = {mode}; received {bytes.Length}.",
                nameof(bytes));
        }

        int finalOracleLength = baseUnit * ScalarSize;

        var roundPolynomials = new CompressedRoundPolynomial[d];
        var foldRoots = new MerkleRoot[d - 1];
        IMemoryOwner<byte>? finalOracleOwner = null;
        var openings = new BaseFoldQueryStep[queryCount][];
        BaseFoldMaskOpening? mask = null;
        bool success = false;

        try
        {
            int cursor = 0;

            for(int i = 0; i < d; i++)
            {
                roundPolynomials[i] = CompressedRoundPolynomial.FromCompressedBytes(
                    bytes.Slice(cursor, RoundPolynomialBytes), RoundPolynomialDegree, curve, pool);
                cursor += RoundPolynomialBytes;
            }

            for(int i = 0; i < d - 1; i++)
            {
                foldRoots[i] = MerkleRoot.FromBytes(bytes.Slice(cursor, digestSize), pool);
                cursor += digestSize;
            }

            finalOracleOwner = pool.Rent(finalOracleLength);
            bytes.Slice(cursor, finalOracleLength).CopyTo(finalOracleOwner.Memory.Span[..finalOracleLength]);
            cursor += finalOracleLength;

            cursor = ReadOpenings(bytes, cursor, openings, queryCount, d, baseUnit, digestSize, hiding, pool);

            if(zeroKnowledge)
            {
                mask = ReadMaskOpening(bytes, ref cursor, parameters, queryCount, digestSize, pool);
            }

            var proof = new BaseFoldEvaluationProof(parameters, queryCount, roundPolynomials, foldRoots, finalOracleOwner, finalOracleLength, openings, mask);
            success = true;

            return proof;
        }
        finally
        {
            if(!success)
            {
                foreach(CompressedRoundPolynomial polynomial in roundPolynomials)
                {
                    polynomial?.Dispose();
                }

                foreach(MerkleRoot root in foldRoots)
                {
                    root?.Dispose();
                }

                finalOracleOwner?.Dispose();

                foreach(BaseFoldQueryStep[]? query in openings)
                {
                    if(query is not null)
                    {
                        foreach(BaseFoldQueryStep step in query)
                        {
                            step?.Dispose();
                        }
                    }
                }

                mask?.Dispose();
            }
        }
    }


    //Reads one side's per-query openings into the supplied jagged array; returns
    //the advanced cursor. The total-length guard has already run, so the slices
    //are in bounds.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "Each reconstructed path and step transfers ownership to the openings array, which the caller's failure path disposes.")]
    private static int ReadOpenings(
        ReadOnlySpan<byte> bytes,
        int cursor,
        BaseFoldQueryStep[][] openings,
        int queryCount,
        int d,
        int baseUnit,
        int digestSize,
        bool hiding,
        BaseMemoryPool pool)
    {
        for(int q = 0; q < queryCount; q++)
        {
            var steps = new BaseFoldQueryStep[d];
            for(int s = 0; s < d; s++)
            {
                int level = d - s;
                int pathBytes = PathDepth(baseUnit, level) * digestSize;

                ReadOnlySpan<byte> first = bytes.Slice(cursor, ScalarSize);
                cursor += ScalarSize;
                ReadOnlySpan<byte> second = bytes.Slice(cursor, ScalarSize);
                cursor += ScalarSize;

                ReadOnlySpan<byte> firstSalt = default;
                ReadOnlySpan<byte> secondSalt = default;
                if(hiding)
                {
                    firstSalt = bytes.Slice(cursor, ScalarSize);
                    cursor += ScalarSize;
                    secondSalt = bytes.Slice(cursor, ScalarSize);
                    cursor += ScalarSize;
                }

                MerkleAuthenticationPath firstPath = ReadPath(bytes.Slice(cursor, pathBytes), digestSize, pool);
                cursor += pathBytes;
                MerkleAuthenticationPath secondPath = ReadPath(bytes.Slice(cursor, pathBytes), digestSize, pool);
                cursor += pathBytes;

                steps[s] = hiding
                    ? BaseFoldQueryStep.CreateSalted(level, first, second, firstSalt, secondSalt, firstPath, secondPath, pool)
                    : BaseFoldQueryStep.Create(level, first, second, firstPath, secondPath, pool);
            }

            openings[q] = steps;
        }

        return cursor;
    }


    //Reads the statistical-ZK mask side: com(C*)'s root, σ, σ_F, then the
    //nested hiding weighted opening at the deterministic mask-commitment shape.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "The root, the σ/σ_F buffers, and the nested proof all transfer ownership to the returned BaseFoldMaskOpening; on a mid-read throw the partially-built pieces are released here before rethrowing.")]
    private static BaseFoldMaskOpening ReadMaskOpening(
        ReadOnlySpan<byte> bytes,
        ref int cursor,
        FoldableCodeParameters parameters,
        int queryCount,
        int digestSize,
        BaseMemoryPool pool)
    {
        MerkleRoot? commitmentRoot = null;
        IMemoryOwner<byte>? sigmaOwner = null;
        IMemoryOwner<byte>? fillerSumOwner = null;
        bool success = false;

        try
        {
            commitmentRoot = MerkleRoot.FromBytes(bytes.Slice(cursor, digestSize), pool);
            cursor += digestSize;

            sigmaOwner = pool.Rent(ScalarSize);
            bytes.Slice(cursor, ScalarSize).CopyTo(sigmaOwner.Memory.Span[..ScalarSize]);
            cursor += ScalarSize;

            fillerSumOwner = pool.Rent(ScalarSize);
            bytes.Slice(cursor, ScalarSize).CopyTo(fillerSumOwner.Memory.Span[..ScalarSize]);
            cursor += ScalarSize;

            FoldableCodeParameters nestedParameters = MaskCommitmentParameters(parameters, queryCount);
            int nestedLength = ComputeLength(nestedParameters, queryCount, digestSize, BaseFoldOpeningMode.Hiding);
            BaseFoldEvaluationProof weightedOpening = FromBytes(
                bytes.Slice(cursor, nestedLength), nestedParameters, queryCount, digestSize, BaseFoldOpeningMode.Hiding, pool);
            cursor += nestedLength;

            BaseFoldMaskOpening mask = new(commitmentRoot, sigmaOwner, fillerSumOwner, ScalarSize, weightedOpening);
            success = true;

            return mask;
        }
        finally
        {
            if(!success)
            {
                commitmentRoot?.Dispose();
                sigmaOwner?.Dispose();
                fillerSumOwner?.Dispose();
            }
        }
    }


    //The deterministic shape of the mask's coefficient commitment for a witness
    //protocol of the given parameters: the policy's lifted layer count under the
    //same classical-security code family and curve.
    private static FoldableCodeParameters MaskCommitmentParameters(FoldableCodeParameters parameters, int queryCount)
    {
        StatisticalMaskParameters maskParameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(parameters.LayerCount, parameters.Curve, queryCount);

        return WellKnownFoldableCodeParameters.CreateClassicalSecurity(maskParameters.LiftedVariableCount, parameters.Curve);
    }


    internal static int ComputeLength(FoldableCodeParameters parameters, int queryCount, int digestSize, BaseFoldOpeningMode mode)
    {
        int d = parameters.LayerCount;
        int baseUnit = parameters.InverseRate * parameters.BaseDimension;
        bool hiding = mode is BaseFoldOpeningMode.Hiding or BaseFoldOpeningMode.ZeroKnowledge;

        long length = (long)d * RoundPolynomialBytes;
        length += (long)(d - 1) * digestSize;
        length += (long)baseUnit * ScalarSize;
        length += QuerySectionLength(d, baseUnit, digestSize, queryCount, hiding);

        //The statistical-ZK mask side: com(C*)'s root, σ, σ_F, then the nested
        //hiding weighted opening at the deterministic mask-commitment shape.
        if(mode is BaseFoldOpeningMode.ZeroKnowledge)
        {
            length += digestSize;
            length += 2L * ScalarSize;
            length += ComputeLength(MaskCommitmentParameters(parameters, queryCount), queryCount, digestSize, BaseFoldOpeningMode.Hiding);
        }

        return checked((int)length);
    }


    //The byte length of one side's per-query opening section.
    private static long QuerySectionLength(int d, int baseUnit, int digestSize, int queryCount, bool hiding)
    {
        //A hiding opening adds the two leaf salts (one scalar each) per step.
        long saltBytesPerStep = hiding ? 2L * ScalarSize : 0L;

        long perQuery = 0;
        for(int s = 0; s < d; s++)
        {
            int level = d - s;
            int pathBytes = PathDepth(baseUnit, level) * digestSize;
            perQuery += (2L * ScalarSize) + saltBytesPerStep + (2L * pathBytes);
        }

        return perQuery * queryCount;
    }


    //The Merkle tree over layer-level's codeword has n_level = baseUnit·2^level
    //leaves, so its depth (and a leaf's path length in siblings) is
    //log2(baseUnit·2^level). The wired code has baseUnit = c·k0 a power of two.
    private static int PathDepth(int baseUnit, int level)
    {
        int leafCount = baseUnit << level;
        return BitOperations.Log2((uint)leafCount);
    }


    private static MerkleAuthenticationPath ReadPath(ReadOnlySpan<byte> pathBytes, int digestSize, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(pathBytes.Length);
        pathBytes.CopyTo(owner.Memory.Span[..pathBytes.Length]);

        return MerkleAuthenticationPath.Create(owner, digestSize);
    }


    private static int Write(Span<byte> buffer, int cursor, ReadOnlySpan<byte> source)
    {
        source.CopyTo(buffer.Slice(cursor, source.Length));
        return source.Length;
    }
}
