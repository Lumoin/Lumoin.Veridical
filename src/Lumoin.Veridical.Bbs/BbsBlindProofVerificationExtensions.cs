using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Blind BBS selective-disclosure proof verification on
/// <see cref="BbsBlindProof"/>. BlindProofVerify is the verifier-side
/// capability: a holder of the public key checks that a framed blind
/// proof was produced by someone holding a valid blind signature over a
/// vector consistent with the disclosed messages, and that every
/// committed-disclosure commitment opens to the corresponding hidden
/// message.
/// </summary>
/// <remarks>
/// The blind -03 framed proof wire format ships with no published test
/// vectors (Section 10 of the draft); this surface is gated by
/// self-consistency and tamper suites, and the D1/D4/D6/D11 ledger
/// interpretations called out at their decision sites are re-KATed when
/// the regenerated official fixtures land.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsBlindProofVerificationExtensions
{
    extension(BbsBlindProof proof)
    {
        /// <summary>
        /// Verifies a framed blind BBS proof against
        /// <paramref name="publicKey"/> and the supplied disclosed
        /// messages per IETF
        /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Sections 4.2.4
        /// (BlindProofVerify), 4.3.5 (CoreProofVerify), and 5.3
        /// (ProofChallengeCalculate). Returns <see langword="false"/> on
        /// any decode failure, ciphersuite mismatch, index or count
        /// inconsistency, or cryptographic failure; throws only on null
        /// arguments.
        /// </summary>
        /// <param name="publicKey">The signer's public key.</param>
        /// <param name="header">The header bytes the signer bound into the blind signature.</param>
        /// <param name="presentationHeader">The presentation-header bytes the prover bound into this proof.</param>
        /// <param name="issuerMessageCount">The number of signer-known messages <c>L</c> in the signed vector (<c>issuer_known_messages_no</c>).</param>
        /// <param name="disclosedMessages">The disclosed messages, parallel to the disclosed-index vector framed inside the proof.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarNegate">Backend scalar negation (the <c>-cp</c> term of the recomputed announcements).</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation, including the <c>(Y_0, Y_1)</c> committed-disclosure bases).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the proof points and every committed-disclosure commitment <c>C_i</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for the proof points and every <c>C_i</c>.</param>
        /// <param name="g2Add">Backend G2 addition.</param>
        /// <param name="g2ScalarMultiply">Backend G2 scalar multiplication.</param>
        /// <param name="g2IsOnCurve">Backend G2 on-curve validation for the public-key point <c>W</c>.</param>
        /// <param name="g2IsInPrimeOrderSubgroup">Backend G2 prime-order-subgroup validation for <c>W</c>.</param>
        /// <param name="pairing">Backend optimal-ate pairing.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns><see langword="true"/> when the proof is valid AND every committed-disclosure commitment is consistent with its hidden message; <see langword="false"/> otherwise.</returns>
        /// <remarks>
        /// Both the fixed-time challenge equality (which absorbs the
        /// commitments and the recomputed announcements <c>C^_i</c>) and
        /// the pairing check are required; neither subsumes the other
        /// (Section 4.3.5 steps 9-10).
        /// </remarks>
        [SuppressMessage("Reliability", "CA2000", Justification = "The ProofVerifyInit result is disposed in the finally block; when it exists it also owns the decoded Abar, Bbar and D, which the same block otherwise disposes directly.")]
        public bool BlindProofVerify(
            BbsPublicKey publicKey,
            BbsHeader header,
            BbsPresentationHeader presentationHeader,
            int issuerMessageCount,
            ReadOnlyMemory<BbsMessage> disclosedMessages,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarNegateDelegate scalarNegate,
            G1AddDelegate g1Add,
            G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
            G1HashToCurveDelegate g1HashToCurve,
            G1IsOnCurveDelegate g1IsOnCurve,
            G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup,
            G2AddDelegate g2Add,
            G2ScalarMultiplyDelegate g2ScalarMultiply,
            G2IsOnCurveDelegate g2IsOnCurve,
            G2IsInPrimeOrderSubgroupDelegate g2IsInPrimeOrderSubgroup,
            PairingDelegate pairing,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarNegate);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1HashToCurve);
            ArgumentNullException.ThrowIfNull(g1IsOnCurve);
            ArgumentNullException.ThrowIfNull(g1IsInPrimeOrderSubgroup);
            ArgumentNullException.ThrowIfNull(g2Add);
            ArgumentNullException.ThrowIfNull(g2ScalarMultiply);
            ArgumentNullException.ThrowIfNull(g2IsOnCurve);
            ArgumentNullException.ThrowIfNull(g2IsInPrimeOrderSubgroup);
            ArgumentNullException.ThrowIfNull(pairing);
            ArgumentNullException.ThrowIfNull(pool);

            //Ledger entry D1: verification must mirror generation, so the
            //blind api_id is used despite the draft's Section 4.2.4
            //Parameters block naming the core suffix.
            BbsCiphersuite blindCiphersuite = BbsBlindAlgorithm.GetBlindInterface(publicKey.Ciphersuite);
            if(proof.Ciphersuite != blindCiphersuite)
            {
                return false;
            }
            if(issuerMessageCount < 0)
            {
                return false;
            }

            //Ledger entry D6 (fixture-pending): the container already
            //recovered U = (bbs_proof_len - 272) / 32 — WITH the division by
            //octet_scalar_length the draft's Deserialization step 2 omits.
            //U counts the secret_prover_blind slot, so the committed-message
            //count subtracts one slot besides the issuer messages.
            int undisclosedCount = proof.UndisclosedMessageCount;
            int disclosedCount = proof.DisclosedIndexCount;
            if(disclosedMessages.Length != disclosedCount)
            {
                return false;
            }
            int totalMessageCount = undisclosedCount + disclosedCount;
            int committedMessageCount = totalMessageCount - 1 - issuerMessageCount;
            if(committedMessageCount < 0)
            {
                return false;
            }

            //Index intake: the container enforced strict ascent and int
            //range; range against the recovered vector size and the
            //never-disclosable blind slot (position L, ledger entries
            //D3/D4) gate here.
            int[] disclosedIndices = new int[disclosedCount];
            for(int i = 0; i < disclosedCount; i++)
            {
                int index = proof.GetDisclosedIndex(i);
                if(index >= totalMessageCount || index == issuerMessageCount)
                {
                    return false;
                }
                disclosedIndices[i] = index;
            }

            int committedDisclosureCount = proof.CommittedDisclosureCount;
            int[] commitIndexes = new int[committedDisclosureCount];
            for(int i = 0; i < committedDisclosureCount; i++)
            {
                int index = proof.GetCommittedDisclosureIndex(i);
                if(index >= totalMessageCount || index == issuerMessageCount)
                {
                    return false;
                }
                commitIndexes[i] = index;
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsBlindVerifyProof, CurveParameterSet.Bls12Curve381);

            string apiId = blindCiphersuite.Identifier;

            //Decode the framed core proof's G1 points and scalars and every
            //committed-disclosure opening inside try/catch — any malformed
            //slice returns false.
            ReadOnlySpan<byte> coreProofBytes = proof.GetCoreProofBytes();
            G1Point? aBar = null;
            G1Point? bBar = null;
            G1Point? d = null;
            Scalar? eHat = null;
            Scalar? r1Hat = null;
            Scalar? r3Hat = null;
            Scalar? c = null;
            Scalar[]? mHats = null;
            G1Point[]? commitments = null;
            Scalar[]? commitResponses = null;
            try
            {
                aBar = G1Point.FromCanonical(coreProofBytes.Slice(BbsProof.ABarOffset, BbsProof.ABarSizeBytes), CurveParameterSet.Bls12Curve381, pool);
                bBar = G1Point.FromCanonical(coreProofBytes.Slice(BbsProof.BBarOffset, BbsProof.BBarSizeBytes), CurveParameterSet.Bls12Curve381, pool);
                d = G1Point.FromCanonical(coreProofBytes.Slice(BbsProof.DOffset, BbsProof.DSizeBytes), CurveParameterSet.Bls12Curve381, pool);
                eHat = Scalar.FromCanonical(coreProofBytes.Slice(BbsProof.EHatOffset, BbsProof.ScalarSizeBytes), CurveParameterSet.Bls12Curve381, pool);
                r1Hat = Scalar.FromCanonical(coreProofBytes.Slice(BbsProof.R1HatOffset, BbsProof.ScalarSizeBytes), CurveParameterSet.Bls12Curve381, pool);
                r3Hat = Scalar.FromCanonical(coreProofBytes.Slice(BbsProof.R3HatOffset, BbsProof.ScalarSizeBytes), CurveParameterSet.Bls12Curve381, pool);
                c = Scalar.FromCanonical(coreProofBytes.Slice(BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes * undisclosedCount, BbsProof.ScalarSizeBytes), CurveParameterSet.Bls12Curve381, pool);

                mHats = new Scalar[undisclosedCount];
                for(int i = 0; i < undisclosedCount; i++)
                {
                    mHats[i] = Scalar.FromCanonical(coreProofBytes.Slice(BbsProof.CommitmentsOffset + BbsProof.ScalarSizeBytes * i, BbsProof.ScalarSizeBytes), CurveParameterSet.Bls12Curve381, pool);
                }

                commitments = new G1Point[committedDisclosureCount];
                commitResponses = new Scalar[committedDisclosureCount];
                for(int i = 0; i < committedDisclosureCount; i++)
                {
                    commitments[i] = G1Point.FromCanonical(proof.GetCommittedDisclosurePointBytes(i), CurveParameterSet.Bls12Curve381, pool);
                    commitResponses[i] = Scalar.FromCanonical(proof.GetCommittedDisclosureScalarBytes(i), CurveParameterSet.Bls12Curve381, pool);
                }
            }
            catch(ArgumentException)
            {
                aBar?.Dispose();
                bBar?.Dispose();
                d?.Dispose();
                eHat?.Dispose();
                r1Hat?.Dispose();
                r3Hat?.Dispose();
                c?.Dispose();
                DisposeAll(mHats);
                DisposeAll(commitments);
                DisposeAll(commitResponses);

                return false;
            }

            //Assigned inside the disposing try so a throw from any of these
            //allocations still releases everything already rented — including
            //the ten objects decoded from the framed proof — via the finally.
            ImmutableArray<Scalar> disclosedScalarsArray = [];
            ImmutableArray<G1Point> generators = [];
            ImmutableArray<G1Point> blindGenerators = [];
            ImmutableArray<G1Point> committedDisclosureBases = [];

            BbsProofInitResult? initResult = null;
            G1Point?[] recomputedAnnouncements = new G1Point?[committedDisclosureCount];
            try
            {
                disclosedScalarsArray = BbsAlgorithm.MessagesToScalars(disclosedMessages, apiId, hashToScalar, pool);
                generators = BbsAlgorithm.CreateGenerators(issuerMessageCount + 1, apiId, expandMessage, g1HashToCurve, pool);
                blindGenerators = BbsAlgorithm.CreateGenerators(
                    committedMessageCount + 1,
                    BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                    expandMessage,
                    g1HashToCurve,
                    pool);
                committedDisclosureBases = BbsAlgorithm.CreateGenerators(
                    2,
                    BbsBlindAlgorithm.GetCommittedDisclosureApiId(apiId),
                    expandMessage,
                    g1HashToCurve,
                    pool);

                try
                {
                    //octets_to_proof steps 30-32 applied uniformly: every framed
                    //G1 component — the core proof points AND every
                    //committed-disclosure commitment C_i — must decode onto the
                    //curve, must not be the identity, and must lie in the
                    //prime-order subgroup. The container validated structure and
                    //scalar canonicity; point geometry needs the backend, so the
                    //point-validation delegates gate here at the surface.
                    if(!IsValidPoint(aBar!, g1IsOnCurve, g1IsInPrimeOrderSubgroup)
                        || !IsValidPoint(bBar!, g1IsOnCurve, g1IsInPrimeOrderSubgroup)
                        || !IsValidPoint(d!, g1IsOnCurve, g1IsInPrimeOrderSubgroup))
                    {
                        return false;
                    }
                    for(int i = 0; i < committedDisclosureCount; i++)
                    {
                        if(!IsValidPoint(commitments![i], g1IsOnCurve, g1IsInPrimeOrderSubgroup))
                        {
                            return false;
                        }
                    }

                    //octets_to_pubkey steps 2-4.
                    using G2Point w = G2Point.FromCanonical(publicKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                    if(!w.IsOnCurve(g2IsOnCurve) || !w.IsInPrimeOrderSubgroup(g2IsInPrimeOrderSubgroup) || w.IsIdentity)
                    {
                        return false;
                    }

                    //Combined generator vector, exactly mirroring the prover
                    //side (ledger entry D2: both families carry their leading
                    //Q point, so the vector spans totalMessageCount + 1).
                    G1Point[] combinedGenerators = new G1Point[totalMessageCount + 1];
                    combinedGenerators[0] = generators[0];
                    for(int i = 0; i < issuerMessageCount; i++)
                    {
                        combinedGenerators[1 + i] = generators[1 + i];
                    }
                    for(int i = 0; i < blindGenerators.Length; i++)
                    {
                        combinedGenerators[1 + issuerMessageCount + i] = blindGenerators[i];
                    }

                    Scalar[] disclosedScalars = new Scalar[disclosedCount];
                    for(int i = 0; i < disclosedCount; i++)
                    {
                        disclosedScalars[i] = disclosedScalarsArray[i];
                    }
                    int[] undisclosed = BbsProofAlgorithm.ComputeUndisclosedIndices(disclosedIndices, totalMessageCount);

                    initResult = BbsProofAlgorithm.ProofVerifyInit(
                        publicKey,
                        aBar!,
                        bBar!,
                        d!,
                        eHat!,
                        r1Hat!,
                        r3Hat!,
                        c!,
                        mHats!,
                        combinedGenerators,
                        header.Bytes,
                        disclosedIndices,
                        disclosedScalars,
                        undisclosed,
                        apiId,
                        hashToScalar,
                        g1Add,
                        g1MultiScalarMultiply,
                        pool);

                    //CoreProofVerify steps 3-5: C^_i = Y_0 * s^_i +
                    //Y_1 * m^[rank(idx)] - C_i * cp. Ledger entry D11
                    //(fixture-pending): the draft's hats[idx] indexes the m^
                    //vector with the FULL-list index; the consistent reading
                    //maps idx to its rank among the undisclosed indexes. A
                    //committed index that is disclosed has no rank — the
                    //proof is malformed and fails here.
                    using Scalar negChallenge = c!.Negate(scalarNegate, pool);
                    G1Point y0 = committedDisclosureBases[0];
                    G1Point y1 = committedDisclosureBases[1];
                    for(int i = 0; i < committedDisclosureCount; i++)
                    {
                        int rank = FindRankAmongUndisclosed(undisclosed, commitIndexes[i]);
                        if(rank < 0)
                        {
                            return false;
                        }

                        G1Point[] announcementPoints = [y0, y1, commitments![i]];
                        Scalar[] announcementScalars = [commitResponses![i], mHats![rank], negChallenge];
                        recomputedAnnouncements[i] = BbsProofAlgorithm.MultiScalarMultiply(announcementPoints, announcementScalars, g1MultiScalarMultiply, pool);
                    }

                    G1Point[] announcements = new G1Point[committedDisclosureCount];
                    for(int i = 0; i < committedDisclosureCount; i++)
                    {
                        announcements[i] = recomputedAnnouncements[i]!;
                    }

                    //CoreProofVerify steps 7-9: re-derive the shared challenge
                    //with the commitments and the recomputed announcements
                    //absorbed, and compare in fixed time.
                    using Scalar challenge = BbsBlindAlgorithm.CalculateBlindProofChallenge(
                        disclosedIndices,
                        disclosedScalars,
                        initResult,
                        commitIndexes,
                        commitments!,
                        announcements,
                        presentationHeader.Bytes,
                        apiId,
                        hashToScalar,
                        pool);
                    if(!CryptographicOperations.FixedTimeEquals(challenge.AsReadOnlySpan(), c!.AsReadOnlySpan()))
                    {
                        return false;
                    }

                    //CoreProofVerify step 10: e(Abar, W) == e(Bbar, BP2), the
                    //equivalent form of the spec's e(Abar, W) * e(Bbar, -BP2) == 1_GT.
                    using G2Point bp2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, pool);

                    using Fp12Element lhs = aBar!.PairWith(w, pairing, pool);
                    using Fp12Element rhs = bBar!.PairWith(bp2, pairing, pool);

                    return CryptographicOperations.FixedTimeEquals(lhs.AsReadOnlySpan(), rhs.AsReadOnlySpan());
                }
                catch(InvalidOperationException)
                {
                    //Backend decode failures during MSM/pairing — the bytes
                    //decoded as length-valid but are not a valid algebraic
                    //object. Mirrors the core verify surfaces' contract by
                    //returning false rather than propagating.
                    return false;
                }
            }
            finally
            {
                //ProofVerifyInit adopts Abar, Bbar and D into the init result on
                //success, so they are disposed through it; on any path where the
                //result was never created ownership is still here.
                if(initResult is not null)
                {
                    initResult.Dispose();
                }
                else
                {
                    aBar.Dispose();
                    bBar.Dispose();
                    d.Dispose();
                }
                eHat.Dispose();
                r1Hat.Dispose();
                r3Hat.Dispose();
                c.Dispose();
                DisposeAll(mHats);
                DisposeAll(commitments);
                DisposeAll(commitResponses);
                for(int i = 0; i < recomputedAnnouncements.Length; i++)
                {
                    recomputedAnnouncements[i]?.Dispose();
                }
                foreach(Scalar scalar in disclosedScalarsArray)
                {
                    scalar.Dispose();
                }
                foreach(G1Point generator in generators)
                {
                    generator.Dispose();
                }
                foreach(G1Point generator in blindGenerators)
                {
                    generator.Dispose();
                }
                foreach(G1Point basePoint in committedDisclosureBases)
                {
                    basePoint.Dispose();
                }
            }
        }
    }


    private static bool IsValidPoint(G1Point point, G1IsOnCurveDelegate g1IsOnCurve, G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup) =>
        point.IsOnCurve(g1IsOnCurve) && !point.IsIdentity && point.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup);


    /// <summary>
    /// Returns the rank of <paramref name="fullVectorIndex"/> among the
    /// ascending <paramref name="undisclosedIndices"/>, or <c>-1</c> when
    /// the index is not undisclosed (a malformed proof the caller rejects
    /// rather than throws on).
    /// </summary>
    private static int FindRankAmongUndisclosed(ReadOnlySpan<int> undisclosedIndices, int fullVectorIndex)
    {
        for(int i = 0; i < undisclosedIndices.Length; i++)
        {
            if(undisclosedIndices[i] == fullVectorIndex)
            {
                return i;
            }
        }

        return -1;
    }


    private static void DisposeAll<T>(T[]? items) where T: class, IDisposable
    {
        if(items is null)
        {
            return;
        }

        for(int i = 0; i < items.Length; i++)
        {
            items[i]?.Dispose();
        }
    }
}
