using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Text;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Shared algorithmic primitives for the BBS+ Interface operations
/// (KeyGen, Sign, Verify) per IETF
/// <c>draft-irtf-cfrg-bbs-signatures-10</c>. All operations dispatch
/// to backend delegates; this class implements the BBS+-specific
/// composition of those delegates and the spec's deterministic
/// byte-layout rules.
/// </summary>
internal static class BbsAlgorithm
{
    /// <summary>
    /// The uniform-output length the BBS+ generator derivation uses:
    /// <c>L = 48</c> per Section 7.2.2 for BLS12-381-SHA-256.
    /// </summary>
    private const int ExpandLengthBytes = 48;


    /// <summary>Returns <c>apiId || suffix</c> as UTF-8 bytes.</summary>
    public static byte[] ComputeDst(string apiId, string suffix)
    {
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(suffix);
        return Encoding.UTF8.GetBytes(apiId + suffix);
    }


    /// <summary>
    /// Implements <c>create_generators(count, api_id)</c> per Section 4.1.1:
    /// derives <paramref name="count"/> deterministic G1 points from
    /// the BBS+ generator seed string. The first returned point is
    /// <c>Q_1</c>; subsequent points are <c>H_1, ..., H_{count-1}</c>.
    /// </summary>
    public static ImmutableArray<G1Point> CreateGenerators(
        int count,
        string apiId,
        ExpandMessageDelegate expandMessage,
        G1HashToCurveDelegate hashToCurve,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(expandMessage);
        ArgumentNullException.ThrowIfNull(hashToCurve);
        ArgumentNullException.ThrowIfNull(pool);
        if(count <= 0)
        {
            return ImmutableArray<G1Point>.Empty;
        }

        byte[] seedDst = ComputeDst(apiId, WellKnownBbsDomainSeparationTags.SignatureGeneratorSeedDstSuffix);
        byte[] generatorDst = ComputeDst(apiId, WellKnownBbsDomainSeparationTags.SignatureGeneratorDstSuffix);
        byte[] initialSeed = Encoding.UTF8.GetBytes(apiId + WellKnownBbsDomainSeparationTags.MessageGeneratorSeedSuffix);

        Span<byte> v = stackalloc byte[ExpandLengthBytes];
        expandMessage(initialSeed, seedDst, v);

        Span<byte> nextSeed = stackalloc byte[ExpandLengthBytes + 8];
        ImmutableArray<G1Point>.Builder builder = ImmutableArray.CreateBuilder<G1Point>(count);

        for(int i = 1; i <= count; i++)
        {
            //v = expand_message(v || I2OSP(i, 8), seed_dst, expand_len)
            v.CopyTo(nextSeed);
            BinaryPrimitives.WriteUInt64BigEndian(nextSeed[ExpandLengthBytes..], (ulong)i);
            expandMessage(nextSeed, seedDst, v);

            G1Point generator = G1Point.FromHashToCurve(v, generatorDst, hashToCurve, CurveParameterSet.Bls12Curve381, pool);
            builder.Add(generator);
        }


        return builder.MoveToImmutable();
    }


    /// <summary>
    /// Implements <c>messages_to_scalars(messages, api_id)</c> per
    /// Section 4.2.1: hashes each message to a scalar using
    /// <c>MAP_MSG_TO_SCALAR_AS_HASH_</c> DST.
    /// </summary>
    public static ImmutableArray<Scalar> MessagesToScalars(
        ReadOnlyMemory<BbsMessage> messages,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        if(messages.IsEmpty)
        {
            return ImmutableArray<Scalar>.Empty;
        }

        byte[] mapDst = ComputeDst(apiId, WellKnownBbsDomainSeparationTags.MapMessageToScalarDstSuffix);
        ImmutableArray<Scalar>.Builder builder = ImmutableArray.CreateBuilder<Scalar>(messages.Length);
        for(int i = 0; i < messages.Length; i++)
        {
            Scalar scalar = Scalar.FromHashToScalar(
                messages.Span[i].Bytes.Span,
                mapDst,
                hashToScalar,
                CurveParameterSet.Bls12Curve381,
                pool);
            builder.Add(scalar);
        }

        return builder.MoveToImmutable();
    }


    /// <summary>
    /// Implements <c>calculate_domain(PK, Q_1, H_Points, header, api_id)</c>
    /// per Section 4.2.3: serialises the domain input as
    /// <c>PK || serialize((L, Q_1, H_1, ..., H_L)) || api_id ||
    /// I2OSP(len(header), 8) || header</c> and hashes to a scalar.
    /// </summary>
    public static Scalar CalculateDomain(
        BbsPublicKey publicKey,
        G1Point q1,
        ReadOnlySpan<G1Point> hPoints,
        ReadOnlyMemory<byte> header,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(q1);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] apiIdBytes = Encoding.UTF8.GetBytes(apiId);
        byte[] h2sDst = ComputeDst(apiId, WellKnownBbsDomainSeparationTags.HashToScalarDstSuffix);

        int hCount = hPoints.Length;
        //dom_input = PK || I2OSP(L, 8) || Q_1 || H_1 || ... || H_L || api_id || I2OSP(len(header), 8) || header
        //where serialize((L, Q_1, H_1, ..., H_L)) = I2OSP(L, 8) || Q_1 || ... || H_L per Section 4.4.1
        //(L is an integer between 0 and 2^64-1, encoded as 8 bytes;
        //Q_i, H_i are G1 points encoded with point_to_octets_E1).
        int domInputLength =
            BbsPublicKey.SizeBytes
            + 8
            + WellKnownCurves.Bls12Curve381G1CompressedSizeBytes * (1 + hCount)
            + apiIdBytes.Length
            + 8
            + header.Length;

        using IMemoryOwner<byte> domInputOwner = pool.Rent(domInputLength);
        Span<byte> domInput = domInputOwner.Memory.Span[..domInputLength];
        Span<byte> cursor = domInput;

        publicKey.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[BbsPublicKey.SizeBytes..];

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)hCount);
        cursor = cursor[8..];

        q1.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes..];

        for(int i = 0; i < hCount; i++)
        {
            hPoints[i].AsReadOnlySpan().CopyTo(cursor);
            cursor = cursor[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes..];
        }

        apiIdBytes.CopyTo(cursor);
        cursor = cursor[apiIdBytes.Length..];

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)header.Length);
        cursor = cursor[8..];

        header.Span.CopyTo(cursor);

        return Scalar.FromHashToScalar(domInput, h2sDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }


    /// <summary>
    /// Implements the <c>e</c> derivation per CoreSign step 2:
    /// <c>e = hash_to_scalar(serialize((SK, msg_1, ..., msg_L, domain)), api_id || "H2S_")</c>.
    /// </summary>
    public static Scalar DeriveSigningScalar(
        BbsSecretKey secretKey,
        ReadOnlySpan<Scalar> messageScalars,
        Scalar domain,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(secretKey);
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] h2sDst = ComputeDst(apiId, WellKnownBbsDomainSeparationTags.HashToScalarDstSuffix);

        int totalLength = BbsSecretKey.SizeBytes
            + Scalar.SizeBytes * messageScalars.Length
            + Scalar.SizeBytes;
        using IMemoryOwner<byte> eInputOwner = pool.Rent(totalLength);
        Span<byte> eInput = eInputOwner.Memory.Span[..totalLength];
        Span<byte> cursor = eInput;

        secretKey.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[BbsSecretKey.SizeBytes..];

        for(int i = 0; i < messageScalars.Length; i++)
        {
            messageScalars[i].AsReadOnlySpan().CopyTo(cursor);
            cursor = cursor[Scalar.SizeBytes..];
        }

        domain.AsReadOnlySpan().CopyTo(cursor);

        return Scalar.FromHashToScalar(eInput, h2sDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }


    /// <summary>
    /// Computes <c>B = P1 + Q_1·domain + sum_i H_i · msg_i</c> per
    /// CoreSign step 3 and CoreVerify step 2. Returns a G1 point
    /// wrapping a freshly-rented buffer.
    /// </summary>
    public static G1Point ComputeMessageCommitment(
        G1Point p1,
        G1Point q1,
        Scalar domain,
        ReadOnlySpan<G1Point> hPoints,
        ReadOnlySpan<Scalar> messageScalars,
        G1AddDelegate g1Add,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(p1);
        ArgumentNullException.ThrowIfNull(q1);
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        int hCount = hPoints.Length;
        if(messageScalars.Length != hCount)
        {
            throw new ArgumentException("Number of H points must equal number of message scalars.");
        }

        //Flatten (Q_1, H_1, ..., H_L) and (domain, msg_1, ..., msg_L) into MSM-friendly buffers.
        int pairCount = 1 + hCount;
        int pointsConcatenatedLength = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes * pairCount;
        int scalarsConcatenatedLength = Scalar.SizeBytes * pairCount;
        using IMemoryOwner<byte> pointsConcatenatedOwner = pool.Rent(pointsConcatenatedLength);
        using IMemoryOwner<byte> scalarsConcatenatedOwner = pool.Rent(scalarsConcatenatedLength);
        Span<byte> pointsConcatenated = pointsConcatenatedOwner.Memory.Span[..pointsConcatenatedLength];
        Span<byte> scalarsConcatenated = scalarsConcatenatedOwner.Memory.Span[..scalarsConcatenatedLength];

        q1.AsReadOnlySpan().CopyTo(pointsConcatenated[..WellKnownCurves.Bls12Curve381G1CompressedSizeBytes]);
        domain.AsReadOnlySpan().CopyTo(scalarsConcatenated[..Scalar.SizeBytes]);

        for(int i = 0; i < hCount; i++)
        {
            hPoints[i].AsReadOnlySpan().CopyTo(pointsConcatenated.Slice(WellKnownCurves.Bls12Curve381G1CompressedSizeBytes * (1 + i), WellKnownCurves.Bls12Curve381G1CompressedSizeBytes));
            messageScalars[i].AsReadOnlySpan().CopyTo(scalarsConcatenated.Slice(Scalar.SizeBytes * (1 + i), Scalar.SizeBytes));
        }

        //MSM produces Q_1·domain + sum H_i · msg_i.
        IMemoryOwner<byte> msmOwner = pool.Rent(WellKnownCurves.Bls12Curve381G1CompressedSizeBytes);
        try
        {
            g1MultiScalarMultiply(
                pointsConcatenated,
                scalarsConcatenated,
                pairCount,
                msmOwner.Memory.Span[..WellKnownCurves.Bls12Curve381G1CompressedSizeBytes],
                CurveParameterSet.Bls12Curve381);
            using G1Point msm = new(msmOwner, CurveParameterSet.Bls12Curve381, WellKnownAlgebraicTags.G1PointFor(CurveParameterSet.Bls12Curve381));

            //B = P1 + MSM.
            return p1.Add(msm, g1Add, pool);
        }
        catch
        {
            msmOwner.Dispose();
            throw;
        }
    }
}