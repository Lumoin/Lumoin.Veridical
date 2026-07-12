using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Shared algorithmic primitives for the Blind BBS Interface operations
/// (Commit, BlindSign, VerifyBlindSign) per IETF
/// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>. All operations
/// dispatch to backend delegates; this class implements the
/// blind-specific composition of those delegates and the draft's
/// deterministic byte-layout rules, reusing the core primitives in
/// <see cref="BbsAlgorithm"/> and <see cref="BbsProofAlgorithm"/> under
/// the blind api_id.
/// </summary>
internal static class BbsBlindAlgorithm
{
    /// <summary>
    /// Maps a ciphersuite to its Blind BBS Interface value: the
    /// interface a key tagged with a core suite signs and verifies
    /// blind material under.
    /// </summary>
    /// <exception cref="InvalidOperationException">When <paramref name="ciphersuite"/> is not one of the six well-known values.</exception>
    public static BbsCiphersuite GetBlindInterface(BbsCiphersuite ciphersuite)
    {
        BbsCiphersuite baseSuite = ciphersuite.BaseHashSuite;

        return baseSuite == BbsCiphersuite.Bls12Curve381Sha256
            ? BbsCiphersuite.Bls12Curve381Sha256Blind
            : BbsCiphersuite.Bls12Curve381Shake256Blind;
    }


    /// <summary>
    /// Returns the api_id the blind (prover/commitment) generators are
    /// derived under: <c>"BLIND_" || api_id</c> per Sections 4.2.1
    /// through 4.2.4 — a second, independent generator family from the
    /// same <c>create_generators</c> machinery.
    /// </summary>
    public static string GetBlindGeneratorApiId(string apiId)
    {
        ArgumentNullException.ThrowIfNull(apiId);

        return WellKnownBbsCiphersuites.BlindGeneratorApiIdPrefix + apiId;
    }


    /// <summary>
    /// Returns the api_id the committed-disclosure bases
    /// <c>(Y_0, Y_1)</c> are derived under: <c>"COM_DIS_" || api_id</c>
    /// per Section 4.3.4 Parameters — a third generator family, disjoint
    /// from both the signer and the blind generators, so a
    /// committed-disclosure commitment can never alias a message slot.
    /// </summary>
    public static string GetCommittedDisclosureApiId(string apiId)
    {
        ArgumentNullException.ThrowIfNull(apiId);

        return WellKnownBbsCiphersuites.CommittedDisclosureGeneratorApiIdPrefix + apiId;
    }


    /// <summary>
    /// Implements <c>calculate_blind_challenge</c> per Section 5.2:
    /// serialises <c>(M, Q_2, J_1, ..., J_M, C, Cbar)</c> — the
    /// committed-message count, all blind generators in derivation
    /// order, the commitment, and the announcement — and hashes to a
    /// scalar via the <c>api_id || "H2S_"</c> DST.
    /// </summary>
    /// <param name="blindGenerators">The blind generator vector <c>(Q_2, J_1, ..., J_M)</c>; must contain at least <c>Q_2</c>.</param>
    /// <param name="commitment">The Pedersen commitment <c>C</c>.</param>
    /// <param name="cBar">The Schnorr announcement <c>Cbar</c>.</param>
    /// <param name="apiId">The Blind BBS Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    public static Scalar CalculateBlindChallenge(
        ReadOnlySpan<G1Point> blindGenerators,
        G1Point commitment,
        G1Point cBar,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(cBar);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);
        if(blindGenerators.Length < 1)
        {
            throw new ArgumentException("calculate_blind_challenge requires at least the Q_2 blind generator.", nameof(blindGenerators));
        }

        int committedMessageCount = blindGenerators.Length - 1;
        int pointBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

        //serialize(c_arr): I2OSP(M, 8) || Q_2 (48) || J_1..J_M (48 each) || C (48) || Cbar (48).
        int totalLength = 8 + pointBytes * (blindGenerators.Length + 2);
        using IMemoryOwner<byte> cOctsOwner = pool.Rent(totalLength);
        Span<byte> cOcts = cOctsOwner.Memory.Span[..totalLength];
        Span<byte> cursor = cOcts;

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)committedMessageCount);
        cursor = cursor[8..];

        for(int i = 0; i < blindGenerators.Length; i++)
        {
            blindGenerators[i].AsReadOnlySpan().CopyTo(cursor);
            cursor = cursor[pointBytes..];
        }

        commitment.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        cBar.AsReadOnlySpan().CopyTo(cursor);

        byte[] h2sDst = BbsAlgorithm.ComputeDst(apiId, WellKnownBbsDomainSeparationTags.HashToScalarDstSuffix);

        return Scalar.FromHashToScalar(cOcts, h2sDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }


    /// <summary>
    /// Implements <c>CoreCommitVerify</c> per Section 4.3.2: recomputes
    /// the Schnorr announcement
    /// <c>Cbar = Q_2 * s^ + sum_i J_i * m^_i - C * cp</c> from the
    /// commitment proof's responses, re-derives the blind challenge, and
    /// compares it against the proof's challenge in fixed time.
    /// </summary>
    /// <param name="commitment">The decoded commitment point <c>C</c>, already validated (on-curve, non-identity, prime-order subgroup) by the caller.</param>
    /// <param name="commitmentWithProof">The wire container carrying <c>s^</c>, the <c>m^_i</c> responses, and the challenge <c>cp</c>.</param>
    /// <param name="blindGenerators">The blind generator vector <c>(Q_2, J_1, ..., J_M)</c>; its length must be <c>M + 1</c> for the proof's <c>M</c> responses.</param>
    /// <param name="apiId">The Blind BBS Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="scalarNegate">Backend scalar negation (for <c>-cp</c>).</param>
    /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    public static bool CoreCommitVerify(
        G1Point commitment,
        BbsCommitmentWithProof commitmentWithProof,
        ReadOnlySpan<G1Point> blindGenerators,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        ScalarNegateDelegate scalarNegate,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(commitment);
        ArgumentNullException.ThrowIfNull(commitmentWithProof);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(scalarNegate);
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        int committedMessageCount = commitmentWithProof.CommittedMessageCount;

        //Arity gate: the blind generator vector destructures as (Q_2, J_1..J_M),
        //so it must hold M + 1 points. (The -03 text says "!= M" here, but the
        //surrounding operations and the -02 text agree on M + 1: taken literally
        //the -03 check could never pass for a commitment that already satisfied
        //deserialize_and_validate_commit's own M + 1 gate.)
        if(blindGenerators.Length != committedMessageCount + 1)
        {
            return false;
        }

        using Scalar sHat = Scalar.FromCanonical(commitmentWithProof.GetSHatBytes(), CurveParameterSet.Bls12Curve381, pool);
        using Scalar challenge = Scalar.FromCanonical(commitmentWithProof.GetChallengeBytes(), CurveParameterSet.Bls12Curve381, pool);
        using Scalar negChallenge = challenge.Negate(scalarNegate, pool);

        Scalar[] mHats = new Scalar[committedMessageCount];
        try
        {
            for(int i = 0; i < committedMessageCount; i++)
            {
                mHats[i] = Scalar.FromCanonical(commitmentWithProof.GetMHatBytes(i), CurveParameterSet.Bls12Curve381, pool);
            }

            //Cbar = Q_2 * s^ + sum_i J_i * m^_i + C * (-cp): one MSM over M + 2 pairs.
            G1Point[] cBarPoints = new G1Point[blindGenerators.Length + 1];
            Scalar[] cBarScalars = new Scalar[blindGenerators.Length + 1];
            cBarPoints[0] = blindGenerators[0];
            cBarScalars[0] = sHat;
            for(int i = 0; i < committedMessageCount; i++)
            {
                cBarPoints[1 + i] = blindGenerators[1 + i];
                cBarScalars[1 + i] = mHats[i];
            }
            cBarPoints[^1] = commitment;
            cBarScalars[^1] = negChallenge;

            using G1Point cBar = BbsProofAlgorithm.MultiScalarMultiply(cBarPoints, cBarScalars, g1MultiScalarMultiply, pool);
            using Scalar recomputedChallenge = CalculateBlindChallenge(blindGenerators, commitment, cBar, apiId, hashToScalar, pool);

            return CryptographicOperations.FixedTimeEquals(
                recomputedChallenge.AsReadOnlySpan(),
                challenge.AsReadOnlySpan());
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
    /// Implements <c>deserialize_and_validate_commit</c> per Section
    /// 4.1.2: an absent commitment yields the Identity_G1 "default"
    /// commit that every downstream computation absorbs as a no-op; a
    /// present one must decode to a non-identity, on-curve, prime-order
    /// point whose Schnorr proof of opening verifies against the blind
    /// generators.
    /// </summary>
    /// <param name="commitmentWithProof">The commitment to validate, or <see langword="null"/> for the no-commitment default.</param>
    /// <param name="blindGenerators">The blind generator vector <c>(Q_2, J_1, ..., J_M)</c>.</param>
    /// <param name="apiId">The Blind BBS Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="scalarNegate">Backend scalar negation.</param>
    /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
    /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the commitment point <c>C</c>.</param>
    /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for <c>C</c>.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    /// <returns>The validated commitment point (owned by the caller), or <see langword="null"/> when validation fails.</returns>
    /// <remarks>
    /// The subgroup check on <c>C</c> is applied even though Section
    /// 5.4.2 does not spell it out: Section 5.4.4 requires
    /// <c>subgroup_check_G1</c> for the structurally identical
    /// commitment points inside proofs, and a cofactor component in
    /// <c>C</c> would survive into the signed point <c>B</c>.
    /// </remarks>
    public static G1Point? DeserializeAndValidateCommit(
        BbsCommitmentWithProof? commitmentWithProof,
        ReadOnlySpan<G1Point> blindGenerators,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        ScalarNegateDelegate scalarNegate,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        G1IsOnCurveDelegate g1IsOnCurve,
        G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(scalarNegate);
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
        ArgumentNullException.ThrowIfNull(g1IsOnCurve);
        ArgumentNullException.ThrowIfNull(g1IsInPrimeOrderSubgroup);
        ArgumentNullException.ThrowIfNull(pool);

        if(commitmentWithProof is null)
        {
            return G1Point.Identity(CurveParameterSet.Bls12Curve381, pool);
        }

        if(blindGenerators.Length != commitmentWithProof.CommittedMessageCount + 1)
        {
            return null;
        }

        G1Point commitment = G1Point.FromCanonical(commitmentWithProof.GetCBytes(), CurveParameterSet.Bls12Curve381, pool);
        try
        {
            //octets_to_commitment_with_proof steps 4-6 plus the uniform subgroup
            //rule (see remarks): C must decode onto the curve, must not be the
            //identity (only an ABSENT commitment yields the identity default; an
            //explicit identity encoding is rejected), and must lie in the
            //prime-order subgroup.
            if(!commitment.IsOnCurve(g1IsOnCurve) || commitment.IsIdentity || !commitment.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup))
            {
                commitment.Dispose();

                return null;
            }

            if(!CoreCommitVerify(commitment, commitmentWithProof, blindGenerators, apiId, hashToScalar, scalarNegate, g1MultiScalarMultiply, pool))
            {
                commitment.Dispose();

                return null;
            }

            return commitment;
        }
        catch
        {
            commitment.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Implements the blind <c>e</c> derivation per FinalizeBlindSign
    /// step 2-3 (Section 4.3.3):
    /// <c>e = hash_to_scalar(serialize((SK, B, domain)), api_id || "H2S_")</c>.
    /// The point <c>B</c> stands in for the message scalars that core
    /// Sign would bind, because the signer does not know the committed
    /// messages hidden inside the commitment absorbed into <c>B</c>.
    /// </summary>
    /// <param name="secretKey">The signing key whose bytes lead the serialization.</param>
    /// <param name="b">The signed point <c>B</c>, fully assembled (domain term, message terms, commitment, and any entropy terms already absorbed).</param>
    /// <param name="domain">
    /// The domain scalar to bind into the <c>e</c> input, or
    /// <see langword="null"/> to derive <c>e</c> over <c>serialize((SK, B))</c>
    /// alone. The blind -03 text binds the domain here, but the
    /// per-verifier-pseudonym -03 test vectors — the only published
    /// fixtures exercising <c>FinalizeBlindSign</c> — pin the
    /// domain-free form byte-for-byte (the domain still reaches <c>e</c>
    /// indirectly through the <c>Q_1 * domain</c> term inside <c>B</c>),
    /// so the pseudonym Interface passes <see langword="null"/> and the
    /// blind Interface keeps the drafted binding until its own fixtures
    /// land.
    /// </param>
    /// <param name="apiId">The extension Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    public static Scalar DeriveBlindSigningScalar(
        BbsSecretKey secretKey,
        G1Point b,
        Scalar? domain,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(secretKey);
        ArgumentNullException.ThrowIfNull(b);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] h2sDst = BbsAlgorithm.ComputeDst(apiId, WellKnownBbsDomainSeparationTags.HashToScalarDstSuffix);

        //serialize((SK, B[, domain])) = SK (32) || B (48, point_to_octets_E1) [|| domain (32)].
        int totalLength = BbsSecretKey.SizeBytes
            + WellKnownCurves.Bls12Curve381G1CompressedSizeBytes
            + (domain is null ? 0 : Scalar.SizeBytes);
        using IMemoryOwner<byte> eInputOwner = pool.Rent(totalLength);
        Span<byte> eInput = eInputOwner.Memory.Span[..totalLength];
        Span<byte> cursor = eInput;

        secretKey.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[BbsSecretKey.SizeBytes..];

        b.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes..];

        domain?.AsReadOnlySpan().CopyTo(cursor);

        return Scalar.FromHashToScalar(eInput, h2sDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }


    /// <summary>
    /// Implements <c>CoreCommit</c> per Section 4.3.1 over pre-mapped
    /// message scalars: draws the <c>M + 2</c> random scalars in the
    /// draft-fixed order (<c>secret_prover_blind</c>, <c>s~</c>,
    /// <c>m~_1..m~_M</c>), forms the Pedersen commitment
    /// <c>C = Q_2 * secret_prover_blind + sum_i J_i * msg_i</c> and its
    /// Schnorr proof of opening, and serialises
    /// <c>C || s^ || m^_1..m^_M || challenge</c>. Scalar-level entry
    /// point so the Blind BBS Interface (message-derived scalars) and the
    /// per-verifier-pseudonym Interface (message-derived scalars plus the
    /// prover's raw nym scalars in the tail slots) compose the same
    /// subroutine.
    /// </summary>
    /// <param name="committedMessageScalars">The full committed scalar vector, in commitment order; the caller retains ownership.</param>
    /// <param name="blindGenerators">The blind generator vector <c>(Q_2, J_1, ..., J_M)</c>; must hold exactly one more point than there are scalars.</param>
    /// <param name="apiId">The extension Interface api_id keying the blind challenge.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="scalarAdd">Backend scalar addition.</param>
    /// <param name="scalarMultiply">Backend scalar multiplication.</param>
    /// <param name="randomScalars">Backend random-scalar source; exactly <c>M + 2</c> scalars are drawn.</param>
    /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    /// <returns>The serialized commitment-with-proof octets (a pool-rented owner the caller wraps or disposes) and the <c>secret_prover_blind</c> scalar the caller owns.</returns>
    public static (IMemoryOwner<byte> CommitmentWithProofOctets, Scalar SecretProverBlind) CoreCommit(
        ReadOnlySpan<Scalar> committedMessageScalars,
        ReadOnlySpan<G1Point> blindGenerators,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarRandomDelegate randomScalars,
        G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarMultiply);
        ArgumentNullException.ThrowIfNull(randomScalars);
        ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
        ArgumentNullException.ThrowIfNull(pool);

        int committedMessageCount = committedMessageScalars.Length;
        if(blindGenerators.Length != committedMessageCount + 1)
        {
            throw new ArgumentException("CoreCommit requires one blind generator per committed scalar plus Q_2.", nameof(blindGenerators));
        }

        //CoreCommit step 1: ONE calculate_random_scalars(M + 2) draw in the
        //draft-fixed order (secret_prover_blind, s~, m~_1..m~_M) — the order
        //is load-bearing for mocked-RNG fixture reproduction.
        int randomScalarCount = committedMessageCount + 2;
        Scalar?[] randoms = new Scalar?[randomScalarCount];
        Scalar[] mHats = new Scalar[committedMessageCount];
        try
        {
            for(int i = 0; i < randomScalarCount; i++)
            {
                randoms[i] = Scalar.FromRandom(randomScalars, CurveParameterSet.Bls12Curve381, pool);
            }

            Scalar secretProverBlind = randoms[0]!;
            Scalar sTilde = randoms[1]!;

            //CoreCommit step 2: C = Q_2 * secret_prover_blind + sum_i J_i * msg_i.
            G1Point[] msmPoints = new G1Point[committedMessageCount + 1];
            Scalar[] msmScalars = new Scalar[committedMessageCount + 1];
            msmPoints[0] = blindGenerators[0];
            msmScalars[0] = secretProverBlind;
            for(int i = 0; i < committedMessageCount; i++)
            {
                msmPoints[1 + i] = blindGenerators[1 + i];
                msmScalars[1 + i] = committedMessageScalars[i];
            }
            using G1Point c = BbsProofAlgorithm.MultiScalarMultiply(msmPoints, msmScalars, g1MultiScalarMultiply, pool);

            //CoreCommit step 3: Cbar = Q_2 * s~ + sum_i J_i * m~_i (same
            //generators, announcement randomness in the message slots).
            msmScalars[0] = sTilde;
            for(int i = 0; i < committedMessageCount; i++)
            {
                msmScalars[1 + i] = randoms[2 + i]!;
            }
            using G1Point cBar = BbsProofAlgorithm.MultiScalarMultiply(msmPoints, msmScalars, g1MultiScalarMultiply, pool);

            //CoreCommit step 4: challenge over (M, Q_2, J_1..J_M, C, Cbar).
            using Scalar challenge = CalculateBlindChallenge(blindGenerators, c, cBar, apiId, hashToScalar, pool);

            //CoreCommit step 5: s^ = s~ + secret_prover_blind * challenge.
            using Scalar blindTimesChallenge = secretProverBlind.Multiply(challenge, scalarMultiply, pool);
            using Scalar sHat = sTilde.Add(blindTimesChallenge, scalarAdd, pool);

            //CoreCommit step 6: m^_i = m~_i + msg_i * challenge.
            for(int i = 0; i < committedMessageCount; i++)
            {
                using Scalar messageTimesChallenge = committedMessageScalars[i].Multiply(challenge, scalarMultiply, pool);
                mHats[i] = randoms[2 + i]!.Add(messageTimesChallenge, scalarAdd, pool);
            }

            //CoreCommit steps 7-8: serialise C || s^ || m^_1..m^_M || challenge.
            int sizeBytes = BbsCommitmentWithProof.ComputeSizeBytes(committedMessageCount);
            IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
            try
            {
                Span<byte> destination = owner.Memory.Span[..sizeBytes];
                c.AsReadOnlySpan().CopyTo(destination[BbsCommitmentWithProof.COffset..]);
                sHat.AsReadOnlySpan().CopyTo(destination.Slice(BbsCommitmentWithProof.SHatOffset, BbsCommitmentWithProof.ScalarSizeBytes));
                for(int i = 0; i < committedMessageCount; i++)
                {
                    mHats[i].AsReadOnlySpan().CopyTo(destination.Slice(
                        BbsCommitmentWithProof.MessageHatsOffset + BbsCommitmentWithProof.ScalarSizeBytes * i,
                        BbsCommitmentWithProof.ScalarSizeBytes));
                }
                challenge.AsReadOnlySpan().CopyTo(destination.Slice(
                    BbsCommitmentWithProof.MessageHatsOffset + BbsCommitmentWithProof.ScalarSizeBytes * committedMessageCount,
                    BbsCommitmentWithProof.ScalarSizeBytes));

                //Ownership of secret_prover_blind transfers to the returned
                //tuple; the finally block's null-tolerant sweep skips it.
                randoms[0] = null;

                return (owner, secretProverBlind);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            for(int i = 0; i < randoms.Length; i++)
            {
                randoms[i]?.Dispose();
            }
            for(int i = 0; i < mHats.Length; i++)
            {
                mHats[i]?.Dispose();
            }
        }
    }


    /// <summary>
    /// Implements the blind <c>ProofChallengeCalculate</c> per Section
    /// 5.3: serialises the core challenge array
    /// <c>(R, i1, msg_i1, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, domain)</c>,
    /// then the committed-disclosure block
    /// <c>(N, i_1, C_1, C~_1, ..., i_N, C_N, C~_N)</c>, then the
    /// <c>I2OSP(len(ph), 8) || ph</c> tail, and hashes to a scalar via
    /// the <c>api_id || "H2S_"</c> DST.
    /// </summary>
    /// <param name="disclosedIndices">The disclosed indices, in the full combined message-vector index space.</param>
    /// <param name="disclosedMessageScalars">The disclosed message scalars, parallel to <paramref name="disclosedIndices"/>.</param>
    /// <param name="initResult">The BBS proof-init tuple whose <c>Abar</c>, <c>Bbar</c>, <c>D</c>, <c>T1</c>, <c>T2</c> and <c>domain</c> are absorbed.</param>
    /// <param name="committedDisclosureIndices">The committed-disclosure indices, in the full combined message-vector index space.</param>
    /// <param name="committedDisclosureCommitments">The commitments <c>C_i</c>, parallel to <paramref name="committedDisclosureIndices"/>.</param>
    /// <param name="committedDisclosureAnnouncements">The announcements — the prover's <c>C~_i</c> or the verifier's recomputed <c>C^_i</c> — parallel to <paramref name="committedDisclosureIndices"/>.</param>
    /// <param name="presentationHeader">The presentation-header bytes.</param>
    /// <param name="apiId">The Blind BBS Interface api_id.</param>
    /// <param name="hashToScalar">Backend hash-to-scalar.</param>
    /// <param name="pool">The pool to rent destination buffers from.</param>
    /// <remarks>
    /// With <c>N = 0</c> the committed-disclosure block is
    /// <c>serialize((0))</c> — eight zero octets — so even a
    /// commitment-free blind proof challenge differs from a core-10
    /// challenge over the same points (on top of the api_id divergence).
    /// This is the interface-separation property Section 5.3 encodes.
    /// </remarks>
    public static Scalar CalculateBlindProofChallenge(
        ReadOnlySpan<int> disclosedIndices,
        ReadOnlySpan<Scalar> disclosedMessageScalars,
        BbsProofInitResult initResult,
        ReadOnlySpan<int> committedDisclosureIndices,
        ReadOnlySpan<G1Point> committedDisclosureCommitments,
        ReadOnlySpan<G1Point> committedDisclosureAnnouncements,
        ReadOnlyMemory<byte> presentationHeader,
        string apiId,
        ScalarHashToScalarDelegate hashToScalar,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(initResult);
        ArgumentNullException.ThrowIfNull(apiId);
        ArgumentNullException.ThrowIfNull(hashToScalar);
        ArgumentNullException.ThrowIfNull(pool);
        if(disclosedIndices.Length != disclosedMessageScalars.Length)
        {
            throw new ArgumentException("Disclosed indices and disclosed message scalars must have the same length.", nameof(disclosedMessageScalars));
        }
        if(committedDisclosureIndices.Length != committedDisclosureCommitments.Length
            || committedDisclosureIndices.Length != committedDisclosureAnnouncements.Length)
        {
            throw new ArgumentException("Committed-disclosure indices, commitments and announcements must have the same length.", nameof(committedDisclosureCommitments));
        }

        int r = disclosedIndices.Length;
        int n = committedDisclosureIndices.Length;
        int pointBytes = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
        int scalarBytes = Scalar.SizeBytes;

        //serialize(c_arr): I2OSP(R, 8)
        //                  || for i in 1..R: I2OSP(idx_i, 8) || msg_scalar_i (32)
        //                  || Abar || Bbar || D || T1 || T2 (48 each)
        //                  || domain (32)
        //c_octs = serialized || I2OSP(N, 8)
        //                    || for i in 1..N: I2OSP(idx_i, 8) || C_i (48) || C~_i (48)
        //                    || I2OSP(len(ph), 8) || ph
        int totalLength =
            8
            + r * (8 + scalarBytes)
            + 5 * pointBytes
            + scalarBytes
            + 8
            + n * (8 + 2 * pointBytes)
            + 8 + presentationHeader.Length;
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

        initResult.ABar.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.BBar.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.D.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.T1.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.T2.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[pointBytes..];
        initResult.Domain.AsReadOnlySpan().CopyTo(cursor);
        cursor = cursor[scalarBytes..];

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)n);
        cursor = cursor[8..];

        for(int i = 0; i < n; i++)
        {
            BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)committedDisclosureIndices[i]);
            cursor = cursor[8..];
            committedDisclosureCommitments[i].AsReadOnlySpan().CopyTo(cursor);
            cursor = cursor[pointBytes..];
            committedDisclosureAnnouncements[i].AsReadOnlySpan().CopyTo(cursor);
            cursor = cursor[pointBytes..];
        }

        BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)presentationHeader.Length);
        cursor = cursor[8..];
        presentationHeader.Span.CopyTo(cursor);

        byte[] h2sDst = BbsAlgorithm.ComputeDst(apiId, WellKnownBbsDomainSeparationTags.HashToScalarDstSuffix);

        return Scalar.FromHashToScalar(cOcts, h2sDst, hashToScalar, CurveParameterSet.Bls12Curve381, pool);
    }


    /// <summary>
    /// Implements <c>proof_to_octets</c> per Section 5.4.3: frames the
    /// core-layout proof bytes, the disclosed indexes, the
    /// committed-disclosure commitments and response scalars, and the
    /// committed-disclosure indexes, each section prefixed with an
    /// 8-byte big-endian count, into a pool-rented buffer of
    /// <see cref="BbsBlindProof.ComputeSizeBytes"/> bytes.
    /// </summary>
    /// <param name="coreProofBytes">The wrapped core-layout proof octets from <c>BBS.ProofFinalize</c>.</param>
    /// <param name="disclosedIndices">The disclosed indexes, in the full combined message-vector index space.</param>
    /// <param name="committedDisclosureCommitments">The commitments <c>C_i</c>.</param>
    /// <param name="committedDisclosureResponses">The response scalars <c>s^_i</c>, parallel to the commitments.</param>
    /// <param name="committedDisclosureIndices">The committed-disclosure indexes, in the full combined message-vector index space.</param>
    /// <param name="pool">The pool to rent the destination buffer from.</param>
    /// <returns>A pool-rented owner the caller wraps in a <see cref="BbsBlindProof"/> or disposes on failure.</returns>
    public static IMemoryOwner<byte> SerializeBlindProof(
        ReadOnlySpan<byte> coreProofBytes,
        ReadOnlySpan<int> disclosedIndices,
        ReadOnlySpan<G1Point> committedDisclosureCommitments,
        ReadOnlySpan<Scalar> committedDisclosureResponses,
        ReadOnlySpan<int> committedDisclosureIndices,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(committedDisclosureCommitments.Length != committedDisclosureResponses.Length
            || committedDisclosureCommitments.Length != committedDisclosureIndices.Length)
        {
            throw new ArgumentException("Committed-disclosure commitments, responses and indexes must have the same length.", nameof(committedDisclosureResponses));
        }

        int undisclosedMessageCount = (coreProofBytes.Length - BbsProof.MinimumSizeBytes) / BbsProof.ScalarSizeBytes;
        int n = committedDisclosureCommitments.Length;
        int totalLength = BbsBlindProof.ComputeSizeBytes(undisclosedMessageCount, disclosedIndices.Length, n);

        IMemoryOwner<byte> owner = pool.Rent(totalLength);
        try
        {
            Span<byte> destination = owner.Memory.Span[..totalLength];
            Span<byte> cursor = destination;

            BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)coreProofBytes.Length);
            cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
            coreProofBytes.CopyTo(cursor);
            cursor = cursor[coreProofBytes.Length..];

            BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)disclosedIndices.Length);
            cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
            for(int i = 0; i < disclosedIndices.Length; i++)
            {
                BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)disclosedIndices[i]);
                cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
            }

            BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)n);
            cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
            for(int i = 0; i < n; i++)
            {
                committedDisclosureCommitments[i].AsReadOnlySpan().CopyTo(cursor);
                cursor = cursor[BbsBlindProof.CommittedDisclosurePointSizeBytes..];
            }
            for(int i = 0; i < n; i++)
            {
                committedDisclosureResponses[i].AsReadOnlySpan().CopyTo(cursor);
                cursor = cursor[BbsBlindProof.CommittedDisclosureScalarSizeBytes..];
            }

            BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)n);
            cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
            for(int i = 0; i < n; i++)
            {
                BinaryPrimitives.WriteUInt64BigEndian(cursor, (ulong)committedDisclosureIndices[i]);
                cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
