using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Blind BBS selective-disclosure proof generation on
/// <see cref="BbsBlindSignature"/>. BlindProofGen is the prover-side
/// capability: a holder of a blind signature, the committed messages,
/// and <c>secret_prover_blind</c> constructs a zero-knowledge proof of
/// that knowledge, choosing per message whether it is disclosed, hidden,
/// or hidden-with-a-committed-disclosure-commitment.
/// </summary>
/// <remarks>
/// The blind -03 framed proof wire format ships with no published test
/// vectors (Section 10 of the draft: fixtures are being regenerated for
/// committed disclosure). This surface is gated by self-consistency and
/// tamper suites; the interpretation choices it encodes (the D3/D4/D6/D11
/// ledger entries called out at their decision sites below) are re-KATed
/// when the regenerated official fixtures land.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsBlindProofGenerationExtensions
{
    private static readonly ProviderOperation BlindProofGenOperation = new("BbsBlindGenerateProof");


    extension(BbsBlindSignature signature)
    {
        /// <summary>
        /// Produces a blind BBS proof of knowledge of
        /// <paramref name="signature"/> over the full message vector,
        /// applying the three-way DISCLOSE/HIDE/COMMIT map per IETF
        /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Sections 4.2.3
        /// (BlindProofGen), 4.3.4 (CoreProofGen), and 5.3
        /// (ProofChallengeCalculate).
        /// </summary>
        /// <param name="publicKey">The public key paired with the signing key; required because <c>domain</c> binds the public key into the proof.</param>
        /// <param name="header">The header bytes the signer bound into the blind signature.</param>
        /// <param name="presentationHeader">Optional presentation-context bytes the prover binds into this specific proof. May be empty.</param>
        /// <param name="messages">The full signer-known message vector, in signing order.</param>
        /// <param name="committedMessages">The full prover-committed message vector, in commitment order.</param>
        /// <param name="messageDisclosures">One disclosure choice per entry of <paramref name="messages"/>.</param>
        /// <param name="committedMessageDisclosures">One disclosure choice per entry of <paramref name="committedMessages"/>.</param>
        /// <param name="secretProverBlind">The blinding factor returned by <c>Commit</c>, or <see langword="null"/> when the signature was produced without a commitment (the spec's zero default). SECRECY OBLIGATION: it must stay with the prover; supplying a wrong value yields a proof that fails verification.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarSubtract">Backend scalar subtraction.</param>
        /// <param name="scalarMultiply">Backend scalar multiplication.</param>
        /// <param name="scalarNegate">Backend scalar negation.</param>
        /// <param name="scalarInvert">Backend scalar inverse.</param>
        /// <param name="randomScalars">Backend random-scalar source. Two draws are made: <c>5 + U</c> scalars for the core proof, then <c>2 * N</c> scalars for the committed-disclosure commitments and their announcements.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation, including the <c>(Y_0, Y_1)</c> committed-disclosure bases).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the signature point <c>A</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for <c>A</c>.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>The framed proof and the <c>add_zkp_info</c> openings. The openings MUST stay with the prover (see <see cref="BbsBlindProofCommitmentOpenings"/>); the proof travels to the verifier.</returns>
        /// <exception cref="ArgumentException">When the signature is not tagged with the blind interface of the key's ciphersuite; when either disclosure vector's length differs from its message vector's; when a disclosure value is not a defined <see cref="BbsMessageDisclosure"/> member; or when the signature point <c>A</c> fails validation.</exception>
        /// <remarks>
        /// The scalar vector the proof covers is
        /// <c>(signer messages, secret_prover_blind, committed messages)</c>
        /// against <c>(Q_1, H_1..H_L, Q_2, J_1..J_M)</c> — the blind slot
        /// sits at position <c>L</c> between the two message families
        /// (ledger entry D3). Neither disclosure vector can address that
        /// slot, so disclosing or committing <c>secret_prover_blind</c> is
        /// structurally impossible.
        /// </remarks>
        [SuppressMessage("Usage", "CA2208", Justification = "C# 14 extension blocks surface the receiver as a regular parameter; 'signature' is the receiver parameter whose point A fails validation.")]
        [SuppressMessage("Reliability", "CA2000", Justification = "The proof and the openings transfer ownership to the returned tuple; the inner catch disposes the proof owner when construction never completed.")]
        public (BbsBlindProof Proof, BbsBlindProofCommitmentOpenings CommitmentOpenings) BlindProofGen(
            BbsPublicKey publicKey,
            BbsHeader header,
            BbsPresentationHeader presentationHeader,
            ReadOnlyMemory<BbsMessage> messages,
            ReadOnlyMemory<BbsMessage> committedMessages,
            ReadOnlyMemory<BbsMessageDisclosure> messageDisclosures,
            ReadOnlyMemory<BbsMessageDisclosure> committedMessageDisclosures,
            Scalar? secretProverBlind,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarNegateDelegate scalarNegate,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate randomScalars,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
            G1HashToCurveDelegate g1HashToCurve,
            G1IsOnCurveDelegate g1IsOnCurve,
            G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(signature);
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(scalarNegate);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(randomScalars);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1HashToCurve);
            ArgumentNullException.ThrowIfNull(g1IsOnCurve);
            ArgumentNullException.ThrowIfNull(g1IsInPrimeOrderSubgroup);
            ArgumentNullException.ThrowIfNull(pool);

            //Ledger entry D1: the blind api_id is used throughout — the
            //draft's Section 4.2.4 "H2G_HM2S_" Parameters block is an
            //inherited copy-paste error, since a proof only verifies under
            //the api_id it was generated with.
            BbsCiphersuite blindCiphersuite = BbsBlindAlgorithm.GetBlindInterface(publicKey.Ciphersuite);
            if(signature.Ciphersuite != blindCiphersuite)
            {
                throw new ArgumentException("BBS+ signature must be produced under the Blind BBS Interface of the public key's ciphersuite.", nameof(signature));
            }

            int signerMessageCount = messages.Length;
            int committedMessageCount = committedMessages.Length;
            if(messageDisclosures.Length != signerMessageCount)
            {
                throw new ArgumentException("messageDisclosures must have one entry per signer-known message.", nameof(messageDisclosures));
            }
            if(committedMessageDisclosures.Length != committedMessageCount)
            {
                throw new ArgumentException("committedMessageDisclosures must have one entry per committed message.", nameof(committedMessageDisclosures));
            }
            ValidateDisclosureValues(messageDisclosures.Span, nameof(messageDisclosures));
            ValidateDisclosureValues(committedMessageDisclosures.Span, nameof(committedMessageDisclosures));

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsBlindGenerateProof, CurveParameterSet.Bls12Curve381);

            string apiId = blindCiphersuite.Identifier;

            //Full combined scalar vector: (signer messages, secret_prover_blind,
            //committed messages) — total L + 1 + M (ledger entry D3).
            int totalMessageCount = signerMessageCount + 1 + committedMessageCount;

            //Ledger entry D4 (fixture-pending): with the blind slot at
            //position L, every committed-message position shifts by L + 1
            //in the combined index space (j → j + L + 1, the -02
            //prepare_parameters remap the nym -03 draft also spells out).
            //Both the disclosed and the committed-disclosure index vectors
            //are assembled in that shifted space; concatenation preserves
            //ascending order because every shifted index exceeds every
            //signer-message index.
            (int[] combinedDisclosed, int[] commitIndexes) = BuildIndexVectors(
                messageDisclosures.Span,
                committedMessageDisclosures.Span,
                signerMessageCount);
            int undisclosedCount = totalMessageCount - combinedDisclosed.Length;
            int[] undisclosed = BbsProofAlgorithm.ComputeUndisclosedIndices(combinedDisclosed, totalMessageCount);

            //Decode signature into (A, e) and validate A per octets_to_signature
            //steps 5-7; the subgroup check protects the prover's unlinkability
            //exactly as in core GenerateProof.
            using G1Point a = G1Point.FromCanonical(signature.GetABytes(), CurveParameterSet.Bls12Curve381, pool);
            using Scalar e = Scalar.FromCanonical(signature.GetEBytes(), CurveParameterSet.Bls12Curve381, pool);
            if(!a.IsOnCurve(g1IsOnCurve) || a.IsIdentity || !a.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup))
            {
                throw new ArgumentException("BBS+ signature point A must be a non-identity point in the prime-order subgroup.", nameof(signature));
            }

            ImmutableArray<Scalar> signerMessageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);
            ImmutableArray<Scalar> committedMessageScalars = BbsAlgorithm.MessagesToScalars(committedMessages, apiId, hashToScalar, pool);
            ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(signerMessageCount + 1, apiId, expandMessage, g1HashToCurve, pool);
            ImmutableArray<G1Point> blindGenerators = BbsAlgorithm.CreateGenerators(
                committedMessageCount + 1,
                BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                expandMessage,
                g1HashToCurve,
                pool);
            ImmutableArray<G1Point> committedDisclosureBases = BbsAlgorithm.CreateGenerators(
                2,
                BbsBlindAlgorithm.GetCommittedDisclosureApiId(apiId),
                expandMessage,
                g1HashToCurve,
                pool);

            int commitCount = commitIndexes.Length;
            int randomScalarCount = 5 + undisclosedCount;
            Scalar[] randoms = new Scalar[randomScalarCount];
            Scalar?[] commitRandoms = new Scalar?[commitCount];
            Scalar?[] commitAnnouncementRandoms = new Scalar?[commitCount];
            G1Point?[] commitments = new G1Point?[commitCount];
            G1Point?[] announcements = new G1Point?[commitCount];
            Scalar[] commitResponses = new Scalar[commitCount];
            Scalar? zeroBlind = null;
            try
            {
                if(secretProverBlind is null)
                {
                    //The spec's zero default: Q_2 * 0 contributes the identity
                    //but keeps the generator/scalar vectors aligned.
                    zeroBlind = Scalar.FromCanonical(stackalloc byte[Scalar.SizeBytes], CurveParameterSet.Bls12Curve381, pool);
                }
                Scalar blindScalar = secretProverBlind ?? zeroBlind!;

                //Combined generator vector (Q_1, H_1..H_L, Q_2, J_1..J_M)
                //parallel to the combined scalar vector.
                G1Point[] combinedGenerators = new G1Point[totalMessageCount + 1];
                combinedGenerators[0] = generators[0];
                for(int i = 0; i < signerMessageCount; i++)
                {
                    combinedGenerators[1 + i] = generators[1 + i];
                }
                for(int i = 0; i < blindGenerators.Length; i++)
                {
                    combinedGenerators[1 + signerMessageCount + i] = blindGenerators[i];
                }

                Scalar[] combinedScalars = new Scalar[totalMessageCount];
                for(int i = 0; i < signerMessageCount; i++)
                {
                    combinedScalars[i] = signerMessageScalars[i];
                }
                combinedScalars[signerMessageCount] = blindScalar;
                for(int i = 0; i < committedMessageCount; i++)
                {
                    combinedScalars[signerMessageCount + 1 + i] = committedMessageScalars[i];
                }

                //CoreProofGen step 1 (via core-10 CoreProofGen): ONE
                //calculate_random_scalars(5 + U) draw (r1, r2, e~, r1~, r3~,
                //m~_1..m~_U) — the order is load-bearing for mocked-RNG
                //fixture reproduction.
                for(int i = 0; i < randomScalarCount; i++)
                {
                    randoms[i] = Scalar.FromRandom(randomScalars, CurveParameterSet.Bls12Curve381, pool);
                }

                using BbsProofInitResult initResult = BbsProofAlgorithm.ProofInit(
                    publicKey,
                    a,
                    e,
                    combinedGenerators,
                    header.Bytes,
                    combinedScalars,
                    undisclosed,
                    randoms,
                    apiId,
                    hashToScalar,
                    scalarMultiply,
                    scalarNegate,
                    g1Add,
                    g1ScalarMultiply,
                    g1MultiScalarMultiply,
                    pool);

                //CoreProofGen step 4: a SECOND calculate_random_scalars(2N)
                //draw in the draft-fixed order (s_1..s_N, s~_1..s~_N).
                for(int i = 0; i < commitCount; i++)
                {
                    commitRandoms[i] = Scalar.FromRandom(randomScalars, CurveParameterSet.Bls12Curve381, pool);
                }
                for(int i = 0; i < commitCount; i++)
                {
                    commitAnnouncementRandoms[i] = Scalar.FromRandom(randomScalars, CurveParameterSet.Bls12Curve381, pool);
                }

                //CoreProofGen steps 6-9: C_i = Y_0 * s_i + Y_1 * msg_scalar[idx]
                //and C~_i = Y_0 * s~_i + Y_1 * m~[rank(idx)]. Ledger entry D11
                //(fixture-pending): the draft's init_random_scalars[idx + 5]
                //indexes the m~ vector with the FULL-list index, but that vector
                //holds one entry per UNDISCLOSED message — the consistent
                //reading maps idx to its rank among the undisclosed indexes,
                //which is always well-defined because committed messages are by
                //construction undisclosed.
                G1Point y0 = committedDisclosureBases[0];
                G1Point y1 = committedDisclosureBases[1];
                G1Point[] pedersenPoints = [y0, y1];
                for(int i = 0; i < commitCount; i++)
                {
                    int idx = commitIndexes[i];
                    Scalar[] commitmentScalars = [commitRandoms[i]!, combinedScalars[idx]];
                    commitments[i] = BbsProofAlgorithm.MultiScalarMultiply(pedersenPoints, commitmentScalars, g1MultiScalarMultiply, pool);

                    int rank = RankAmongUndisclosed(undisclosed, idx);
                    Scalar[] announcementScalars = [commitAnnouncementRandoms[i]!, randoms[5 + rank]];
                    announcements[i] = BbsProofAlgorithm.MultiScalarMultiply(pedersenPoints, announcementScalars, g1MultiScalarMultiply, pool);
                }

                //Disclosed message scalars, parallel to the combined disclosed
                //indexes.
                Scalar[] disclosedScalars = new Scalar[combinedDisclosed.Length];
                for(int i = 0; i < combinedDisclosed.Length; i++)
                {
                    disclosedScalars[i] = combinedScalars[combinedDisclosed[i]];
                }

                //CoreProofGen step 11: ONE shared challenge over the core
                //c_arr, the committed-disclosure block, and the ph tail.
                G1Point[] commitmentPoints = new G1Point[commitCount];
                G1Point[] announcementPoints = new G1Point[commitCount];
                for(int i = 0; i < commitCount; i++)
                {
                    commitmentPoints[i] = commitments[i]!;
                    announcementPoints[i] = announcements[i]!;
                }
                using Scalar challenge = BbsBlindAlgorithm.CalculateBlindProofChallenge(
                    combinedDisclosed,
                    disclosedScalars,
                    initResult,
                    commitIndexes,
                    commitmentPoints,
                    announcementPoints,
                    presentationHeader.Bytes,
                    apiId,
                    hashToScalar,
                    pool);

                Scalar[] undisclosedScalars = new Scalar[undisclosedCount];
                for(int i = 0; i < undisclosedCount; i++)
                {
                    undisclosedScalars[i] = combinedScalars[undisclosed[i]];
                }

                //CoreProofGen step 13: the core proof bytes under the shared
                //challenge.
                using IMemoryOwner<byte> coreProofOwner = BbsProofAlgorithm.ProofFinalize(
                    initResult,
                    challenge,
                    e,
                    randoms,
                    undisclosedScalars,
                    scalarAdd,
                    scalarSubtract,
                    scalarMultiply,
                    scalarInvert,
                    pool);

                //CoreProofGen step 14: s^_i = s~_i + challenge * s_i.
                for(int i = 0; i < commitCount; i++)
                {
                    using Scalar randomnessTimesChallenge = commitRandoms[i]!.Multiply(challenge, scalarMultiply, pool);
                    commitResponses[i] = commitAnnouncementRandoms[i]!.Add(randomnessTimesChallenge, scalarAdd, pool);
                }

                //CoreProofGen step 16: the framed wire container.
                int coreProofSizeBytes = BbsProof.ComputeSizeBytes(undisclosedCount);
                IMemoryOwner<byte> proofOwner = BbsBlindAlgorithm.SerializeBlindProof(
                    coreProofOwner.Memory.Span[..coreProofSizeBytes],
                    combinedDisclosed,
                    commitmentPoints,
                    commitResponses,
                    commitIndexes,
                    pool);
                BbsBlindProof? proof = null;
                try
                {
                    Tag proofTag = ProviderInstrumentation.StampTag(
                        BbsBlindProof.GetAlgebraicTag(blindCiphersuite),
                        WellKnownBbsProviderIdentities.Library,
                        WellKnownBbsProviderIdentities.Crypto,
                        WellKnownBbsProviderIdentities.Class,
                        BlindProofGenOperation);
                    proof = new BbsBlindProof(proofOwner, undisclosedCount, combinedDisclosed.Length, commitCount, proofTag);

                    //CoreProofGen step 17: add_zkp_info = {commits, commit_rands}.
                    //Ownership of the commitments and their randomness transfers
                    //to the openings; the finally block's null-tolerant sweeps
                    //skip them.
                    G1Point[] openingCommitments = new G1Point[commitCount];
                    Scalar[] openingRandomness = new Scalar[commitCount];
                    for(int i = 0; i < commitCount; i++)
                    {
                        openingCommitments[i] = commitments[i]!;
                        openingRandomness[i] = commitRandoms[i]!;
                        commitments[i] = null;
                        commitRandoms[i] = null;
                    }

                    return (proof, new BbsBlindProofCommitmentOpenings(openingCommitments, openingRandomness));
                }
                catch
                {
                    if(proof is null)
                    {
                        proofOwner.Dispose();
                    }
                    else
                    {
                        proof.Dispose();
                    }
                    throw;
                }
            }
            finally
            {
                zeroBlind?.Dispose();
                for(int i = 0; i < randoms.Length; i++)
                {
                    randoms[i]?.Dispose();
                }
                for(int i = 0; i < commitCount; i++)
                {
                    commitRandoms[i]?.Dispose();
                    commitAnnouncementRandoms[i]?.Dispose();
                    commitments[i]?.Dispose();
                    announcements[i]?.Dispose();
                    commitResponses[i]?.Dispose();
                }
                foreach(Scalar scalar in signerMessageScalars)
                {
                    scalar.Dispose();
                }
                foreach(Scalar scalar in committedMessageScalars)
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


    private static void ValidateDisclosureValues(ReadOnlySpan<BbsMessageDisclosure> disclosures, string parameterName)
    {
        for(int i = 0; i < disclosures.Length; i++)
        {
            if(disclosures[i] is not (BbsMessageDisclosure.Hide or BbsMessageDisclosure.Disclose or BbsMessageDisclosure.Commit))
            {
                throw new ArgumentException($"Disclosure value at position {i} is not a defined BbsMessageDisclosure member.", parameterName);
            }
        }
    }


    /// <summary>
    /// Assembles the disclosed and committed-disclosure index vectors in
    /// the full combined index space: signer positions as-is, committed
    /// positions shifted past the <c>L</c> signer messages and the
    /// <c>secret_prover_blind</c> slot (<c>j → j + L + 1</c>).
    /// </summary>
    private static (int[] DisclosedIndices, int[] CommitIndices) BuildIndexVectors(
        ReadOnlySpan<BbsMessageDisclosure> messageDisclosures,
        ReadOnlySpan<BbsMessageDisclosure> committedMessageDisclosures,
        int signerMessageCount)
    {
        int disclosedCount = 0;
        int commitCount = 0;
        for(int i = 0; i < messageDisclosures.Length; i++)
        {
            if(messageDisclosures[i] == BbsMessageDisclosure.Disclose)
            {
                disclosedCount++;
            }
            else if(messageDisclosures[i] == BbsMessageDisclosure.Commit)
            {
                commitCount++;
            }
        }
        for(int i = 0; i < committedMessageDisclosures.Length; i++)
        {
            if(committedMessageDisclosures[i] == BbsMessageDisclosure.Disclose)
            {
                disclosedCount++;
            }
            else if(committedMessageDisclosures[i] == BbsMessageDisclosure.Commit)
            {
                commitCount++;
            }
        }

        int[] disclosed = new int[disclosedCount];
        int[] commits = new int[commitCount];
        int disclosedWrite = 0;
        int commitWrite = 0;
        for(int i = 0; i < messageDisclosures.Length; i++)
        {
            if(messageDisclosures[i] == BbsMessageDisclosure.Disclose)
            {
                disclosed[disclosedWrite++] = i;
            }
            else if(messageDisclosures[i] == BbsMessageDisclosure.Commit)
            {
                commits[commitWrite++] = i;
            }
        }
        for(int i = 0; i < committedMessageDisclosures.Length; i++)
        {
            if(committedMessageDisclosures[i] == BbsMessageDisclosure.Disclose)
            {
                disclosed[disclosedWrite++] = i + signerMessageCount + 1;
            }
            else if(committedMessageDisclosures[i] == BbsMessageDisclosure.Commit)
            {
                commits[commitWrite++] = i + signerMessageCount + 1;
            }
        }

        return (disclosed, commits);
    }


    /// <summary>
    /// Returns the rank of <paramref name="fullVectorIndex"/> among the
    /// ascending <paramref name="undisclosedIndices"/> — the position of
    /// its <c>m~</c>/<c>m^</c> entry in the per-undisclosed-message
    /// vectors.
    /// </summary>
    internal static int RankAmongUndisclosed(ReadOnlySpan<int> undisclosedIndices, int fullVectorIndex)
    {
        for(int i = 0; i < undisclosedIndices.Length; i++)
        {
            if(undisclosedIndices[i] == fullVectorIndex)
            {
                return i;
            }
        }

        throw new ArgumentException($"Index {fullVectorIndex} is not among the undisclosed indexes.", nameof(fullVectorIndex));
    }
}
