using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Shared algorithmic primitives for the BBS+ proof operations
/// (GenerateProof, VerifyProof) per IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c> Sections 3.6.3
/// (CoreProofGen) and 3.6.4 (CoreProofVerify), with the proof
/// subroutines from Sections 3.7.1 through 3.7.4.
/// </summary>
/// <remarks>
/// <para>
/// All operations dispatch to backend delegates. The composition of
/// those delegates and the spec's deterministic byte-layout rules
/// live here; the public surface (<see cref="BbsProofGenerationExtensions"/> /
/// <see cref="BbsProofVerificationExtensions"/>)
/// is a thin wrapper that validates inputs, stamps provenance, and
/// delegates to these methods.
/// </para>
/// </remarks>
internal static class BbsProofAlgorithm
{
    /// <summary>
    /// Validates that <paramref name="disclosedIndices"/> is a strictly
    /// ascending sequence of non-negative integers, all strictly less
    /// than <paramref name="totalCount"/>.
    /// </summary>
    public static bool AreIndicesValid(ReadOnlySpan<int> disclosedIndices, int totalCount)
    {
        int previous = -1;
        for(int i = 0; i < disclosedIndices.Length; i++)
        {
            int current = disclosedIndices[i];
            if(current <= previous || current < 0 || current >= totalCount)
            {
                return false;
            }
            previous = current;
        }

        return true;
    }


    /// <summary>
    /// Returns the indices in <c>[0, totalCount)</c> that are not in
    /// <paramref name="disclosedIndices"/>, preserving ascending order.
    /// </summary>
    public static int[] ComputeUndisclosedIndices(ReadOnlySpan<int> disclosedIndices, int totalCount)
    {
        int undisclosedCount = totalCount - disclosedIndices.Length;
        int[] result = new int[undisclosedCount];
        int writeIndex = 0;
        int readIndex = 0;
        for(int i = 0; i < totalCount; i++)
        {
            if(readIndex < disclosedIndices.Length && disclosedIndices[readIndex] == i)
            {
                readIndex++;
            }
            else
            {
                result[writeIndex++] = i;
            }
        }

        return result;
    }


    /// <summary>
    /// Computes a G1 multi-scalar multiplication
    /// <c>sum_i (points[i] * scalars[i])</c> via the backend delegate.
    /// </summary>
    public static G1Point MultiScalarMultiply(
        ReadOnlySpan<G1Point> points,
        ReadOnlySpan<Scalar> scalars,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        if(points.Length != scalars.Length)
        {
            throw new ArgumentException("Points and scalars must have the same length.");
        }

        int n = points.Length;
        int pointBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
        int scalarBytes = Scalar.SizeBytes;

        int pointBufLength = pointBytes * n;
        int scalarBufLength = scalarBytes * n;
        using IMemoryOwner<byte> pointBufOwner = pool.Rent(pointBufLength);
        using IMemoryOwner<byte> scalarBufOwner = pool.Rent(scalarBufLength);
        Span<byte> pointBuf = pointBufOwner.Memory.Span[..pointBufLength];
        Span<byte> scalarBuf = scalarBufOwner.Memory.Span[..scalarBufLength];
        for(int i = 0; i < n; i++)
        {
            points[i].AsReadOnlySpan().CopyTo(pointBuf.Slice(i * pointBytes, pointBytes));
            scalars[i].AsReadOnlySpan().CopyTo(scalarBuf.Slice(i * scalarBytes, scalarBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(pointBytes);
        try
        {
            g1MultiScalarMultiply(
                pointBuf,
                scalarBuf,
                n,
                owner.Memory.Span[..pointBytes],
                CurveParameterSet.Bls12Curve381);
            return new G1Point(owner, CurveParameterSet.Bls12Curve381, WellKnownAlgebraicTags.G1PointFor(CurveParameterSet.Bls12Curve381));
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Implements <c>ProofChallengeCalculate</c> per Section 3.7.4.
    /// Serialises <c>(R, i1, msg_i1, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, domain) || I2OSP(len(ph), 8) || ph</c>
    /// and hashes to a scalar via the <c>api_id || "H2S_"</c> DST.
    /// </summary>
    public static Scalar CalculateChallenge(
        ReadOnlySpan<int> disclosedIndices,
        ReadOnlySpan<Scalar> disclosedMessageScalars,
        G1Point aBar,
        G1Point bBar,
        G1Point d,
        G1Point t1,
        G1Point t2,
        Scalar domain,
        ReadOnlyMemory<byte> presentationHeader,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(aBar);
        ArgumentNullException.ThrowIfNull(bBar);
        ArgumentNullException.ThrowIfNull(d);
        ArgumentNullException.ThrowIfNull(t1);
        ArgumentNullException.ThrowIfNull(t2);
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        int r = disclosedIndices.Length;
        int pointBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
        int scalarBytes = Scalar.SizeBytes;

        //serialize(c_arr): I2OSP(R, 8)
        //                  || for i in 1..R: I2OSP(idx_i, 8) || msg_scalar_i (32 bytes)
        //                  || Abar (48) || Bbar (48) || D (48) || T1 (48) || T2 (48)
        //                  || domain (32)
        int serializedLength =
            8
            + r * (8 + scalarBytes)
            + 5 * pointBytes
            + scalarBytes;

        //c_octs = serialized || I2OSP(len(ph), 8) || ph
        int totalLength = serializedLength + 8 + presentationHeader.Length;
        using IMemoryOwner<byte> cOctsOwner = pool.Rent(totalLength);
        Span<byte> cOcts = cOctsOwner.Memory.Span[..totalLength];
        Span<byte> cursor = cOcts;

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)r);
        cursor = cursor[8..];

        for(int i = 0; i < r; i++)
        {
            BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)disclosedIndices[i]);
            cursor = cursor[8..];
            disclosedMessageScalars[i].AsReadOnlySpan().CopyTo(cursor);
            cursor = cursor[scalarBytes..];
        }

        aBar.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        bBar.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        d.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        t1.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        t2.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        domain.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[scalarBytes..];

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)presentationHeader.Length);
        cursor = cursor[8..];
        presentationHeader.Span.CopyTo(cursor);

        byte[] h2sDst = BbsAlgorithm.ComputeDst(apiId, WellKnownBbsDomainSeparationTags.HashToScalarDstSuffix);
        return Scalar.FromHashToScalar(cOcts, h2sDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }
}