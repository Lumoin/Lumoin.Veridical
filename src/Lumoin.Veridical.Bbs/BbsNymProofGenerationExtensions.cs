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
/// Per-verifier-pseudonym selective-disclosure proof generation on
/// <see cref="BbsBlindSignature"/>. ProofGenWithNym is the prover-side
/// capability: a holder of a pseudonym-Interface blind signature and the
/// finalized <c>nym_secrets</c> constructs a zero-knowledge proof of
/// that knowledge bound to a verifier-specific pseudonym, revealing only
/// a chosen subset of the signer-known and committed messages — never
/// the nym secrets or the blinding factor.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsNymProofGenerationExtensions
{
    private static readonly ProviderOperation ProofGenWithNymOperation = new("BbsNymGenerateProof");


    extension(BbsBlindSignature signature)
    {
        /// <summary>
        /// Produces a pseudonym-bound BBS proof of knowledge of
        /// <paramref name="signature"/> over the full message vector,
        /// disclosing only the messages at
        /// <paramref name="disclosedIndices"/> /
        /// <paramref name="disclosedCommittedIndices"/>, per IETF
        /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Sections
        /// 6.2 (ProofGenWithNym), 7.1 (CoreProofGenWithNym), and 7.3.1
        /// (PseudonymProofInit).
        /// </summary>
        /// <param name="publicKey">The public key paired with the signing key; required because <c>domain</c> binds the public key into the proof.</param>
        /// <param name="header">The header bytes the signer bound into the signature (without the length suffix; the nym-vector length is re-derived from <paramref name="nymSecrets"/>).</param>
        /// <param name="presentationHeader">Optional presentation-context bytes the Prover binds into this specific proof. May be empty.</param>
        /// <param name="nymSecrets">The finalized <c>nym_secrets</c> from <c>VerifyFinalizeWithNym</c>; at least one entry. Structurally never disclosable.</param>
        /// <param name="contextId">The verifier-supplied context octets the pseudonym is computed against.</param>
        /// <param name="messages">The full signer-known message vector, in signing order.</param>
        /// <param name="committedMessages">The full prover-committed message vector, in commitment order.</param>
        /// <param name="disclosedIndices">Strictly ascending indices into <paramref name="messages"/> to disclose.</param>
        /// <param name="disclosedCommittedIndices">Strictly ascending indices into <paramref name="committedMessages"/> to disclose; internally remapped past the signer messages and the blind slot (<c>j → j + L + 1</c>).</param>
        /// <param name="secretProverBlind">The blinding factor from <c>CommitWithNym</c>. Structurally never disclosable.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarSubtract">Backend scalar subtraction.</param>
        /// <param name="scalarMultiply">Backend scalar multiplication.</param>
        /// <param name="scalarNegate">Backend scalar negation.</param>
        /// <param name="scalarInvert">Backend scalar inverse.</param>
        /// <param name="randomScalars">Backend random-scalar source. Exactly <c>5 + U</c> scalars are drawn (U = undisclosed count over the full combined vector); the LAST <c>N</c> of them double as the pseudonym proof's blinding polynomial coefficients — the reuse that binds the pseudonym to the BBS proof.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation and the pseudonym base point).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the signature point <c>A</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for <c>A</c>.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>The proof (core BBS wire layout under the pseudonym Interface) and the pseudonym it is bound to. The pseudonym travels alongside the proof to the verifier — it is never concatenated into the proof octets.</returns>
        /// <exception cref="ArgumentException">When the signature is not tagged with the key's pseudonym Interface; when <paramref name="nymSecrets"/> is empty; when either index vector is not strictly ascending or exceeds its message-vector range (disclosing a nym-secret or blind slot is structurally impossible — those positions are not addressable by either index space); when the signature point <c>A</c> fails validation; or when the pseudonym computation degenerates to the identity.</exception>
        [SuppressMessage("Usage", "CA2208", Justification = "C# 14 extension blocks surface the receiver as a regular parameter; 'signature' is the receiver parameter whose point A fails validation.")]
        [SuppressMessage("Reliability", "CA2000", Justification = "The proof and pseudonym transfer ownership to the returned tuple; the inner catch disposes the proof (or its owner when construction never completed) when the pseudonym construction throws before the return.")]
        public (BbsPseudonymProof Proof, BbsPseudonym Pseudonym) ProofGenWithNym(
            BbsPublicKey publicKey,
            BbsHeader header,
            BbsPresentationHeader presentationHeader,
            ReadOnlyMemory<Scalar> nymSecrets,
            ReadOnlyMemory<byte> contextId,
            ReadOnlyMemory<BbsMessage> messages,
            ReadOnlyMemory<BbsMessage> committedMessages,
            ReadOnlyMemory<int> disclosedIndices,
            ReadOnlyMemory<int> disclosedCommittedIndices,
            Scalar secretProverBlind,
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
            ArgumentNullException.ThrowIfNull(secretProverBlind);
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

            BbsCiphersuite pseudonymCiphersuite = BbsPseudonymAlgorithm.GetPseudonymInterface(publicKey.Ciphersuite);
            if(signature.Ciphersuite != pseudonymCiphersuite)
            {
                throw new ArgumentException("BBS+ signature must be produced under the pseudonym Interface of the public key's ciphersuite.", nameof(signature));
            }
            if(nymSecrets.IsEmpty)
            {
                throw new ArgumentException("ProofGenWithNym requires at least one nym_secret scalar.", nameof(nymSecrets));
            }

            int signerMessageCount = messages.Length;
            int committedMessageCount = committedMessages.Length;
            int nymCount = nymSecrets.Length;

            //ProofGenWithNym Deserialization steps 3-6: each index space is
            //validated against its OWN message vector — the blind slot and the
            //nym tail are not addressable from either space, which is what
            //makes disclosing them structurally impossible.
            ReadOnlySpan<int> disclosed = disclosedIndices.Span;
            ReadOnlySpan<int> disclosedCommitted = disclosedCommittedIndices.Span;
            if(!BbsProofAlgorithm.AreIndicesValid(disclosed, signerMessageCount))
            {
                throw new ArgumentException("disclosedIndices must be strictly ascending, deduplicated, and in [0, messages.Length).", nameof(disclosedIndices));
            }
            if(!BbsProofAlgorithm.AreIndicesValid(disclosedCommitted, committedMessageCount))
            {
                throw new ArgumentException("disclosedCommittedIndices must be strictly ascending, deduplicated, and in [0, committedMessages.Length).", nameof(disclosedCommittedIndices));
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsNymGenerateProof, CurveParameterSet.Bls12Curve381);

            string apiId = pseudonymCiphersuite.Identifier;

            //Full combined scalar vector: (signer messages, secret_prover_blind,
            //committed messages, nym_secrets) — total L + 1 + M' + N.
            int totalMessageCount = signerMessageCount + 1 + committedMessageCount + nymCount;
            int disclosedTotal = disclosed.Length + disclosedCommitted.Length;
            int undisclosedCount = totalMessageCount - disclosedTotal;

            //CoreProofGenWithNym Deserialization step 7 (R > L - 1): with the
            //nym tail and the blind slot never addressable the structural bound
            //is strictly tighter, so this arithmetic can never trip; it is kept
            //as the draft's own belt-and-braces gate.
            if(disclosedTotal > totalMessageCount - 1)
            {
                throw new ArgumentException("A pseudonym proof must keep at least the nym secrets undisclosed.", nameof(disclosedIndices));
            }

            //Combined disclosed indexes in the full-vector space: signer indexes
            //as-is, committed indexes shifted past the L signer messages and the
            //secret_prover_blind slot (j → j + L + 1). Concatenation preserves
            //ascending order because every shifted index exceeds every signer one.
            int[] combinedDisclosed = new int[disclosedTotal];
            for(int i = 0; i < disclosed.Length; i++)
            {
                combinedDisclosed[i] = disclosed[i];
            }
            for(int i = 0; i < disclosedCommitted.Length; i++)
            {
                combinedDisclosed[disclosed.Length + i] = disclosedCommitted[i] + signerMessageCount + 1;
            }
            int[] undisclosed = BbsProofAlgorithm.ComputeUndisclosedIndices(combinedDisclosed, totalMessageCount);

            //Decode signature into (A, e) and validate A per octets_to_signature
            //steps 5-7; the subgroup check protects the Prover's unlinkability
            //exactly as in core GenerateProof.
            using G1Point a = G1Point.FromCanonical(signature.GetABytes(), CurveParameterSet.Bls12Curve381, pool);
            using Scalar e = Scalar.FromCanonical(signature.GetEBytes(), CurveParameterSet.Bls12Curve381, pool);
            if(!a.IsOnCurve(g1IsOnCurve) || a.IsIdentity || !a.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup))
            {
                throw new ArgumentException("BBS+ signature point A must be a non-identity point in the prime-order subgroup.", nameof(signature));
            }

            //Assigned inside the disposing try so a throw from any of these
            //allocations still releases everything already rented via the
            //finally.
            ImmutableArray<Scalar> signerMessageScalars = [];
            ImmutableArray<Scalar> committedMessageScalars = [];
            ImmutableArray<G1Point> generators = [];
            ImmutableArray<G1Point> blindGenerators = [];

            int randomScalarCount = 5 + undisclosedCount;
            Scalar[] randoms = new Scalar[randomScalarCount];
            G1Point? pseudonymPoint = null;
            G1Point? announcement = null;
            try
            {
                signerMessageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);
                committedMessageScalars = BbsAlgorithm.MessagesToScalars(committedMessages, apiId, hashToScalar, pool);
                generators = BbsAlgorithm.CreateGenerators(signerMessageCount + 1, apiId, expandMessage, g1HashToCurve, pool);
                blindGenerators = BbsAlgorithm.CreateGenerators(
                    committedMessageCount + nymCount + 1,
                    BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                    expandMessage,
                    g1HashToCurve,
                    pool);

                //Combined generator vector (Q_1, H_1..H_L, Q_2, J_1..J_{M'+N})
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
                combinedScalars[signerMessageCount] = secretProverBlind;
                for(int i = 0; i < committedMessageCount; i++)
                {
                    combinedScalars[signerMessageCount + 1 + i] = committedMessageScalars[i];
                }
                for(int i = 0; i < nymCount; i++)
                {
                    combinedScalars[signerMessageCount + 1 + committedMessageCount + i] = nymSecrets.Span[i];
                }

                //CoreProofGenWithNym step 1: ONE calculate_random_scalars(5 + U)
                //draw (r1, r2, e~, r1~, r3~, m~_1..m~_U) — the order is
                //load-bearing for mocked-RNG fixture reproduction AND for the
                //pseudonym binding, whose blinding values are the last N draws.
                for(int i = 0; i < randomScalarCount; i++)
                {
                    randoms[i] = Scalar.FromRandom(randomScalars, CurveParameterSet.Bls12Curve381, pool);
                }

                //CoreProofGenWithNym step 2: the nym-vector length rides the
                //header into the domain.
                (IMemoryOwner<byte> combinedHeaderOwner, int combinedHeaderLength) = BbsPseudonymAlgorithm.ComputeCombinedHeader(header.Bytes, nymCount, pool);
                using IMemoryOwner<byte> combinedHeader = combinedHeaderOwner;

                using BbsProofInitResult initResult = BbsProofAlgorithm.ProofInit(
                    publicKey,
                    a,
                    e,
                    combinedGenerators,
                    combinedHeader.Memory[..combinedHeaderLength],
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

                //CoreProofGenWithNym step 5: PseudonymProofInit over the LAST N
                //message scalars (the nym_secrets) and the LAST N random scalars
                //— the very m~ values ProofInit consumed for those undisclosed
                //tail slots. The nym secrets are always the last undisclosed
                //messages, so the last N draws are exactly their m~ values.
                (G1Point Pseudonym, G1Point Ut)? pseudonymInit = BbsPseudonymAlgorithm.PseudonymProofInit(
                    nymSecrets.Span,
                    randoms.AsSpan()[^nymCount..],
                    contextId.Span,
                    apiId,
                    hashToScalar,
                    scalarAdd,
                    scalarMultiply,
                    g1HashToCurve,
                    g1ScalarMultiply,
                    pool);
                if(pseudonymInit is null)
                {
                    throw new ArgumentException("The pseudonym computation degenerated to the identity; the nym_secrets vector is invalid for this context.", nameof(nymSecrets));
                }
                (pseudonymPoint, announcement) = pseudonymInit.Value;

                //Disclosed message scalars, parallel to the combined disclosed
                //indexes.
                Scalar[] disclosedScalars = new Scalar[disclosedTotal];
                for(int i = 0; i < disclosedTotal; i++)
                {
                    disclosedScalars[i] = combinedScalars[combinedDisclosed[i]];
                }

                using Scalar challenge = BbsPseudonymAlgorithm.CalculateChallengeWithPseudonym(
                    combinedDisclosed,
                    disclosedScalars,
                    initResult,
                    pseudonymPoint,
                    announcement,
                    contextId.Span,
                    presentationHeader.Bytes,
                    apiId,
                    hashToScalar,
                    pool);

                Scalar[] undisclosedScalars = new Scalar[undisclosedCount];
                for(int i = 0; i < undisclosedCount; i++)
                {
                    undisclosedScalars[i] = combinedScalars[undisclosed[i]];
                }

                IMemoryOwner<byte> proofOwner = BbsProofAlgorithm.ProofFinalize(
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
                BbsPseudonymProof? proof = null;
                try
                {
                    Tag proofTag = ProviderInstrumentation.StampTag(
                        BbsPseudonymProof.GetAlgebraicTag(pseudonymCiphersuite),
                        WellKnownBbsProviderIdentities.Library,
                        WellKnownBbsProviderIdentities.Crypto,
                        WellKnownBbsProviderIdentities.Class,
                        ProofGenWithNymOperation);
                    proof = new BbsPseudonymProof(proofOwner, undisclosedCount, proofTag);

                    Tag pseudonymTag = ProviderInstrumentation.StampTag(
                        BbsPseudonym.GetAlgebraicTag(pseudonymCiphersuite),
                        WellKnownBbsProviderIdentities.Library,
                        WellKnownBbsProviderIdentities.Crypto,
                        WellKnownBbsProviderIdentities.Class,
                        ProofGenWithNymOperation);
                    BbsPseudonym pseudonym = BbsPseudonym.FromCanonical(pseudonymPoint.AsReadOnlySpan(), pseudonymCiphersuite, pool, pseudonymTag);

                    return (proof, pseudonym);
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
                pseudonymPoint?.Dispose();
                announcement?.Dispose();
                for(int i = 0; i < randoms.Length; i++)
                {
                    randoms[i]?.Dispose();
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
            }
        }
    }
}
