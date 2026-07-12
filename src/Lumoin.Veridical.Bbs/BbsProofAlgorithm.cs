using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

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
    /// Implements <c>ProofInit</c> per Section 3.7.1: computes the
    /// commitments <c>(Abar, Bbar, D, T1, T2)</c> and the <c>domain</c>
    /// scalar from the deserialized signature <c>(A, e)</c> and the
    /// pre-drawn random scalars. The returned result owns all six
    /// components; the caller disposes it after the challenge and
    /// finalization steps.
    /// </summary>
    /// <param name="publicKey">The public key bound into <c>domain</c>; its ciphersuite selects <c>P1</c>.</param>
    /// <param name="a">The deserialized signature point <c>A</c>, already validated by the caller.</param>
    /// <param name="e">The deserialized signature scalar <c>e</c>.</param>
    /// <param name="generators">The full generator vector: element 0 plays <c>Q_1</c>, the rest are the <c>H</c> points, one per message scalar.</param>
    /// <param name="header">The header bytes the signer bound into the signature.</param>
    /// <param name="messageScalars">All message scalars, in signing order.</param>
    /// <param name="undisclosedIndices">The ascending indices of the messages the proof keeps hidden.</param>
    /// <param name="randomScalars">The <c>5 + U</c> pre-drawn scalars in draw order: <c>r1, r2, e~, r1~, r3~, m~_j...</c>. The caller draws them so extension pipelines can reuse the same randomness across composed subroutines.</param>
    /// <param name="apiId">The api_id string keying the domain-separation tags.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="scalarMultiply">Backend scalar multiplication.</param>
    /// <param name="scalarNegate">Backend scalar negation.</param>
    /// <param name="g1Add">Backend G1 addition.</param>
    /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
    /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    [SuppressMessage("Reliability", "CA2000", Justification = "The six computed components transfer ownership to the returned BbsProofInitResult; on any mid-computation throw the catch disposes whatever was already created before rethrowing.")]
    public static BbsProofInitResult ProofInit(
        BbsPublicKey publicKey,
        G1Point a,
        Scalar e,
        ReadOnlySpan<G1Point> generators,
        ReadOnlyMemory<byte> header,
        ReadOnlySpan<Scalar> messageScalars,
        ReadOnlySpan<int> undisclosedIndices,
        ReadOnlySpan<Scalar> randomScalars,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarNegateDelegate scalarNegate,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMultiply,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarNegate);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        int undisclosedCount = undisclosedIndices.Length;
        if(randomScalars.Length != 5 + undisclosedCount)
        {
            throw new ArgumentException("ProofInit requires exactly 5 + U random scalars (r1, r2, e~, r1~, r3~, m~_j...).", nameof(randomScalars));
        }
        if(generators.Length != messageScalars.Length + 1)
        {
            throw new ArgumentException("ProofInit requires one generator per message scalar plus Q_1.", nameof(generators));
        }

        Scalar r1 = randomScalars[0];
        Scalar r2 = randomScalars[1];
        Scalar eTilde = randomScalars[2];
        Scalar r1Tilde = randomScalars[3];
        Scalar r3Tilde = randomScalars[4];
        ReadOnlySpan<Scalar> mTildes = randomScalars[5..];

        G1Point q1 = generators[0];
        ReadOnlySpan<G1Point> hPoints = generators[1..];

        Scalar? domain = null;
        G1Point? d = null;
        G1Point? aBar = null;
        G1Point? bBar = null;
        G1Point? t1 = null;
        G1Point? t2 = null;
        try
        {
            //domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id).
            domain = BbsAlgorithm.CalculateDomain(publicKey, q1, hPoints, header, apiId, hashToScalar, pool);

            //ProofInit step 2: B = P1 + Q_1 * domain + sum H_i * msg_i.
            using G1Point p1 = BbsP1Generator.GetForCiphersuite(publicKey.Ciphersuite, pool);
            using G1Point b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars, g1Add, g1MultiScalarMultiply, pool);

            //ProofInit step 3: D = B * r2.
            d = b.ScalarMultiply(r2, g1ScalarMultiply, pool);

            //ProofInit step 4: Abar = A * (r1 * r2).
            using Scalar r1TimesR2 = r1.Multiply(r2, scalarMultiply, pool);
            aBar = a.ScalarMultiply(r1TimesR2, g1ScalarMultiply, pool);

            //ProofInit step 5: Bbar = D * r1 - Abar * e = MSM([D, Abar], [r1, -e]).
            using Scalar negE = e.Negate(scalarNegate, pool);
            G1Point[] bBarPoints = [d, aBar];
            Scalar[] bBarScalars = [r1, negE];
            bBar = MultiScalarMultiply(bBarPoints, bBarScalars, g1MultiScalarMultiply, pool);

            //ProofInit step 6: T1 = Abar * e~ + D * r1~ = MSM([Abar, D], [e~, r1~]).
            G1Point[] t1Points = [aBar, d];
            Scalar[] t1Scalars = [eTilde, r1Tilde];
            t1 = MultiScalarMultiply(t1Points, t1Scalars, g1MultiScalarMultiply, pool);

            //ProofInit step 7: T2 = D * r3~ + sum_{j in undisclosed} H_j * m~_j.
            G1Point[] t2Points = new G1Point[1 + undisclosedCount];
            Scalar[] t2Scalars = new Scalar[1 + undisclosedCount];
            t2Points[0] = d;
            t2Scalars[0] = r3Tilde;
            for(int i = 0; i < undisclosedCount; i++)
            {
                t2Points[1 + i] = hPoints[undisclosedIndices[i]];
                t2Scalars[1 + i] = mTildes[i];
            }
            t2 = MultiScalarMultiply(t2Points, t2Scalars, g1MultiScalarMultiply, pool);

            return new BbsProofInitResult(aBar, bBar, d, t1, t2, domain);
        }
        catch
        {
            domain?.Dispose();
            d?.Dispose();
            aBar?.Dispose();
            bBar?.Dispose();
            t1?.Dispose();
            t2?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Implements <c>ProofFinalize</c> per Section 3.7.2: computes the
    /// Schnorr responses <c>(e^, r1^, r3^, m^_j...)</c> and serialises
    /// the proof as <c>Abar || Bbar || D || e^ || r1^ || r3^ || m^_j... || c</c>
    /// into a pool-rented buffer of <see cref="BbsProof.ComputeSizeBytes"/>
    /// bytes. The caller wraps the returned owner in a
    /// <see cref="BbsProof"/> (stamping provenance) or disposes it on
    /// failure.
    /// </summary>
    /// <param name="initResult">The <c>ProofInit</c> output whose <c>Abar</c>, <c>Bbar</c> and <c>D</c> bytes head the proof.</param>
    /// <param name="challenge">The proof challenge <c>c</c>.</param>
    /// <param name="e">The deserialized signature scalar <c>e</c>.</param>
    /// <param name="randomScalars">The same <c>5 + U</c> scalars handed to <c>ProofInit</c>, in draw order: <c>r1, r2, e~, r1~, r3~, m~_j...</c>.</param>
    /// <param name="undisclosedMessageScalars">The scalars of the undisclosed messages, in undisclosed-index order; passed directly (not as indices) so extension pipelines can include hidden scalars that live outside the signed message vector.</param>
    /// <param name="scalarAdd">Backend scalar addition.</param>
    /// <param name="scalarSubtract">Backend scalar subtraction.</param>
    /// <param name="scalarMultiply">Backend scalar multiplication.</param>
    /// <param name="scalarInvert">Backend scalar inverse.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    public static IMemoryOwner<byte> ProofFinalize(
        BbsProofInitResult initResult,
        Scalar challenge,
        Scalar e,
        ReadOnlySpan<Scalar> randomScalars,
        ReadOnlySpan<Scalar> undisclosedMessageScalars,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarInvertDelegate scalarInvert,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(initResult);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarSubtract);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(pool);

        int undisclosedCount = undisclosedMessageScalars.Length;
        if(randomScalars.Length != 5 + undisclosedCount)
        {
            throw new ArgumentException("ProofFinalize requires exactly 5 + U random scalars (r1, r2, e~, r1~, r3~, m~_j...).", nameof(randomScalars));
        }

        Scalar r1 = randomScalars[0];
        Scalar r2 = randomScalars[1];
        Scalar eTilde = randomScalars[2];
        Scalar r1Tilde = randomScalars[3];
        Scalar r3Tilde = randomScalars[4];
        ReadOnlySpan<Scalar> mTildes = randomScalars[5..];

        //ProofFinalize step 1: r3 = r2^-1.
        using Scalar r3 = r2.Invert(scalarInvert, pool);

        //ProofFinalize step 2: e^ = e~ + e * c.
        using Scalar eTimesC = e.Multiply(challenge, scalarMultiply, pool);
        using Scalar eHat = eTilde.Add(eTimesC, scalarAdd, pool);

        //ProofFinalize step 3: r1^ = r1~ - r1 * c.
        using Scalar r1TimesC = r1.Multiply(challenge, scalarMultiply, pool);
        using Scalar r1Hat = r1Tilde.Subtract(r1TimesC, scalarSubtract, pool);

        //ProofFinalize step 4: r3^ = r3~ - r3 * c.
        using Scalar r3TimesC = r3.Multiply(challenge, scalarMultiply, pool);
        using Scalar r3Hat = r3Tilde.Subtract(r3TimesC, scalarSubtract, pool);

        //ProofFinalize step 5: m^_j = m~_j + undisclosed_msg_j * c.
        Scalar[] mHats = new Scalar[undisclosedCount];
        try
        {
            for(int i = 0; i < undisclosedCount; i++)
            {
                using Scalar msgTimesC = undisclosedMessageScalars[i].Multiply(challenge, scalarMultiply, pool);
                mHats[i] = mTildes[i].Add(msgTimesC, scalarAdd, pool);
            }

            //ProofFinalize step 6 + 7: serialise the proof as Abar || Bbar || D || e^ || r1^ || r3^ || m^_j... || c.
            int proofSize = BbsProof.ComputeSizeBytes(undisclosedCount);
            IMemoryOwner<byte> proofOwner = pool.Rent(proofSize);
            try
            {
                Span<byte> dst = proofOwner.Memory.Span[..proofSize];
                initResult.ABar.AsReadOnlySpan().CopyTo(dst[BbsProof.ABarOffset..]);
                initResult.BBar.AsReadOnlySpan().CopyTo(dst[BbsProof.BBarOffset..]);
                initResult.D.AsReadOnlySpan().CopyTo(dst[BbsProof.DOffset..]);
                eHat.AsReadOnlySpan().CopyTo(dst.Slice(BbsProof.EHatOffset, Scalar.SizeBytes));
                r1Hat.AsReadOnlySpan().CopyTo(dst.Slice(BbsProof.R1HatOffset, Scalar.SizeBytes));
                r3Hat.AsReadOnlySpan().CopyTo(dst.Slice(BbsProof.R3HatOffset, Scalar.SizeBytes));
                for(int i = 0; i < undisclosedCount; i++)
                {
                    mHats[i].AsReadOnlySpan()
                        .CopyTo(dst.Slice(BbsProof.CommitmentsOffset + Scalar.SizeBytes * i, Scalar.SizeBytes));
                }
                challenge.AsReadOnlySpan()
                    .CopyTo(dst.Slice(BbsProof.CommitmentsOffset + Scalar.SizeBytes * undisclosedCount, Scalar.SizeBytes));

                return proofOwner;
            }
            catch
            {
                proofOwner.Dispose();
                throw;
            }
        }
        finally
        {
            for(int i = 0; i < mHats.Length; i++)
            {
                mHats[i]?.Dispose();
            }
        }
    }


    /// <summary>
    /// Implements <c>ProofVerifyInit</c> per Section 3.7.3: recomputes
    /// <c>domain</c>, <c>T1 = Bbar * c + Abar * e^ + D * r1^</c> and
    /// <c>T2 = Bv * c + D * r3^ + sum_j H_j * m^_j</c> (with
    /// <c>Bv = P1 + Q_1 * domain + sum_i H_i * msg_i</c> over the
    /// disclosed messages) from the deserialized proof components, so
    /// the caller can re-derive the challenge.
    /// </summary>
    /// <remarks>
    /// On success the returned result adopts <paramref name="aBar"/>,
    /// <paramref name="bBar"/> and <paramref name="d"/> alongside the
    /// freshly computed <c>T1</c>, <c>T2</c> and <c>domain</c>; the
    /// caller then disposes those three points only through the result.
    /// On failure ownership of the three points stays with the caller
    /// and everything computed here is disposed before rethrowing.
    /// </remarks>
    /// <param name="publicKey">The public key bound into <c>domain</c>; its ciphersuite selects <c>P1</c>.</param>
    /// <param name="aBar">The proof point <c>Abar</c>, already validated by the caller.</param>
    /// <param name="bBar">The proof point <c>Bbar</c>, already validated by the caller.</param>
    /// <param name="d">The proof point <c>D</c>, already validated by the caller.</param>
    /// <param name="eHat">The proof scalar <c>e^</c>.</param>
    /// <param name="r1Hat">The proof scalar <c>r1^</c>.</param>
    /// <param name="r3Hat">The proof scalar <c>r3^</c>.</param>
    /// <param name="challenge">The proof scalar <c>c</c>.</param>
    /// <param name="mHats">The proof's undisclosed-message response scalars <c>m^_j...</c>.</param>
    /// <param name="generators">The full generator vector: element 0 plays <c>Q_1</c>, the rest are the <c>H</c> points.</param>
    /// <param name="header">The header bytes the signer bound into the signature.</param>
    /// <param name="disclosedIndices">The ascending indices of the disclosed messages.</param>
    /// <param name="disclosedMessageScalars">The disclosed message scalars, parallel to <paramref name="disclosedIndices"/>.</param>
    /// <param name="undisclosedIndices">The ascending indices not in <paramref name="disclosedIndices"/>, parallel to <paramref name="mHats"/>.</param>
    /// <param name="apiId">The api_id string keying the domain-separation tags.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="g1Add">Backend G1 addition.</param>
    /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    [SuppressMessage("Reliability", "CA2000", Justification = "The computed T1, T2 and domain transfer ownership to the returned BbsProofInitResult alongside the adopted Abar, Bbar and D; on any mid-computation throw the catch disposes the computed components before rethrowing, leaving the adopted points with the caller.")]
    public static BbsProofInitResult ProofVerifyInit(
        BbsPublicKey publicKey,
        G1Point aBar,
        G1Point bBar,
        G1Point d,
        Scalar eHat,
        Scalar r1Hat,
        Scalar r3Hat,
        Scalar challenge,
        ReadOnlySpan<Scalar> mHats,
        ReadOnlySpan<G1Point> generators,
        ReadOnlyMemory<byte> header,
        ReadOnlySpan<int> disclosedIndices,
        ReadOnlySpan<Scalar> disclosedMessageScalars,
        ReadOnlySpan<int> undisclosedIndices,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        G1AddDelegate g1Add,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(aBar);
        ArgumentNullException.ThrowIfNull(bBar);
        ArgumentNullException.ThrowIfNull(d);
        ArgumentNullException.ThrowIfNull(eHat);
        ArgumentNullException.ThrowIfNull(r1Hat);
        ArgumentNullException.ThrowIfNull(r3Hat);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        int r = disclosedIndices.Length;
        int u = undisclosedIndices.Length;

        G1Point q1 = generators[0];
        ReadOnlySpan<G1Point> hPoints = generators[1..];

        Scalar? domain = null;
        G1Point? t1 = null;
        G1Point? t2 = null;
        try
        {
            domain = BbsAlgorithm.CalculateDomain(publicKey, q1, hPoints, header, apiId, hashToScalar, pool);

            //ProofVerifyInit step 2: T1 = Bbar * c + Abar * e^ + D * r1^.
            G1Point[] t1Points = [bBar, aBar, d];
            Scalar[] t1Scalars = [challenge, eHat, r1Hat];
            t1 = MultiScalarMultiply(t1Points, t1Scalars, g1MultiScalarMultiply, pool);

            //ProofVerifyInit step 3: Bv = P1 + Q_1 * domain + sum_{i in disclosed} H_i * msg_i.
            using G1Point p1 = BbsP1Generator.GetForCiphersuite(publicKey.Ciphersuite, pool);
            G1Point[] bvMsmPoints = new G1Point[1 + r];
            Scalar[] bvMsmScalars = new Scalar[1 + r];
            bvMsmPoints[0] = q1;
            bvMsmScalars[0] = domain;
            for(int i = 0; i < r; i++)
            {
                bvMsmPoints[1 + i] = hPoints[disclosedIndices[i]];
                bvMsmScalars[1 + i] = disclosedMessageScalars[i];
            }
            using G1Point bvMsm = MultiScalarMultiply(bvMsmPoints, bvMsmScalars, g1MultiScalarMultiply, pool);
            using G1Point bv = p1.Add(bvMsm, g1Add, pool);

            //ProofVerifyInit step 4: T2 = Bv * c + D * r3^ + sum_{j in undisclosed} H_j * m^_j.
            G1Point[] t2Points = new G1Point[2 + u];
            Scalar[] t2Scalars = new Scalar[2 + u];
            t2Points[0] = bv;
            t2Scalars[0] = challenge;
            t2Points[1] = d;
            t2Scalars[1] = r3Hat;
            for(int i = 0; i < u; i++)
            {
                t2Points[2 + i] = hPoints[undisclosedIndices[i]];
                t2Scalars[2 + i] = mHats[i];
            }
            t2 = MultiScalarMultiply(t2Points, t2Scalars, g1MultiScalarMultiply, pool);

            return new BbsProofInitResult(aBar, bBar, d, t1, t2, domain);
        }
        catch
        {
            domain?.Dispose();
            t1?.Dispose();
            t2?.Dispose();
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