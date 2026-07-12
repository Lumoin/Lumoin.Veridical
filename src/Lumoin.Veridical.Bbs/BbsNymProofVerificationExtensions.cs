using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Per-verifier-pseudonym selective-disclosure proof verification on
/// <see cref="BbsPublicKey"/>. ProofVerifyWithNym is the Verifier-side
/// capability: a holder of the public key checks that a proof was
/// produced by someone holding a valid pseudonym-Interface signature
/// whose hidden nym secrets also produced the presented pseudonym under
/// the verifier's <c>context_id</c>.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsNymProofVerificationExtensions
{
    extension(BbsPublicKey publicKey)
    {
        /// <summary>
        /// Verifies a pseudonym-bound BBS proof against
        /// <paramref name="publicKey"/>, <paramref name="pseudonym"/>,
        /// <paramref name="contextId"/>, and the supplied disclosed
        /// messages and indices, per IETF
        /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Sections
        /// 6.3 (ProofVerifyWithNym), 7.2 (CoreProofVerifyWithNym), and
        /// 7.3.2 (PseudonymProofVerifyInit). Returns <see langword="false"/>
        /// on any decode failure, ciphersuite mismatch, index or count
        /// inconsistency, or cryptographic failure; throws only on null
        /// arguments.
        /// </summary>
        /// <param name="proof">The proof to verify (core BBS wire layout under the pseudonym Interface).</param>
        /// <param name="pseudonym">The pseudonym presented alongside the proof. Its intake type already refuses the identity and BP1 encodings; this surface additionally requires it to decode onto the curve and into the prime-order subgroup.</param>
        /// <param name="header">The header bytes the Signer bound into the signature underlying the proof (without the length suffix).</param>
        /// <param name="presentationHeader">The presentation-header bytes the Prover bound into this proof.</param>
        /// <param name="contextId">The verifier's context octets the pseudonym is claimed under.</param>
        /// <param name="lengthNymVector">The prover-declared nym-vector length <c>N</c>. Folded into the domain and used to slice the nym response scalars off the proof's tail — a value differing from the one the signer certified fails the challenge comparison (the Sybil-resistance binding).</param>
        /// <param name="signerMessageCount">The total number of signer-known messages <c>L</c> in the signed vector.</param>
        /// <param name="disclosedMessages">The disclosed signer-known messages, parallel to <paramref name="disclosedIndices"/>.</param>
        /// <param name="disclosedCommittedMessages">The disclosed prover-committed messages, parallel to <paramref name="disclosedCommittedIndices"/>.</param>
        /// <param name="disclosedIndices">Strictly ascending indices into the signer-known vector.</param>
        /// <param name="disclosedCommittedIndices">Strictly ascending indices into the committed vector; internally remapped <c>j → j + L + 1</c>.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition (polynomial evaluation).</param>
        /// <param name="scalarMultiply">Backend scalar multiplication (polynomial evaluation).</param>
        /// <param name="scalarNegate">Backend scalar negation (the <c>-cp</c> term of <c>Uv</c>).</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation and the pseudonym base point).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the proof points and the pseudonym.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for the proof points and the pseudonym.</param>
        /// <param name="g2Add">Backend G2 addition.</param>
        /// <param name="g2ScalarMultiply">Backend G2 scalar multiplication.</param>
        /// <param name="g2IsOnCurve">Backend G2 on-curve validation for the public-key point <c>W</c>.</param>
        /// <param name="g2IsInPrimeOrderSubgroup">Backend G2 prime-order-subgroup validation for <c>W</c>.</param>
        /// <param name="pairing">Backend optimal-ate pairing.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns><see langword="true"/> when the proof is valid AND the pseudonym is consistent with the hidden nym secrets; <see langword="false"/> otherwise.</returns>
        /// <remarks>
        /// Both the challenge equality (which absorbs the pseudonym and
        /// the recomputed announcement <c>Uv</c>) and the pairing check
        /// are required; neither subsumes the other (Section 7.2 steps
        /// 6-7).
        /// </remarks>
        [SuppressMessage("Reliability", "CA2000", Justification = "The ProofVerifyInit result is disposed in the finally block; when it exists it also owns the decoded Abar, Bbar and D, which the same block otherwise disposes directly.")]
        public bool ProofVerifyWithNym(
            BbsPseudonymProof proof,
            BbsPseudonym pseudonym,
            BbsHeader header,
            BbsPresentationHeader presentationHeader,
            ReadOnlyMemory<byte> contextId,
            int lengthNymVector,
            int signerMessageCount,
            ReadOnlyMemory<BbsMessage> disclosedMessages,
            ReadOnlyMemory<BbsMessage> disclosedCommittedMessages,
            ReadOnlyMemory<int> disclosedIndices,
            ReadOnlyMemory<int> disclosedCommittedIndices,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
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
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(pseudonym);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
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

            //The proof and the pseudonym must both carry the exact pseudonym
            //Interface of the key's base suite.
            BbsCiphersuite pseudonymCiphersuite = BbsPseudonymAlgorithm.GetPseudonymInterface(publicKey.Ciphersuite);
            if(proof.Ciphersuite != pseudonymCiphersuite || pseudonym.Ciphersuite != pseudonymCiphersuite)
            {
                return false;
            }
            if(lengthNymVector < 1 || signerMessageCount < 0)
            {
                return false;
            }

            ReadOnlySpan<int> disclosed = disclosedIndices.Span;
            ReadOnlySpan<int> disclosedCommitted = disclosedCommittedIndices.Span;
            if(disclosedMessages.Length != disclosed.Length || disclosedCommittedMessages.Length != disclosedCommitted.Length)
            {
                return false;
            }

            //ProofVerifyWithNym Deserialization steps 3-5: recover the blind-side
            //slot count M (secret_prover_blind + committed messages + nym
            //secrets) from the proof length and the disclosed counts. The
            //declared nym-vector length must fit inside the committed slots.
            int u = proof.UndisclosedMessageCount;
            int totalMessageCount = disclosed.Length + disclosedCommitted.Length + u;
            int blindSideSlotCount = totalMessageCount - 1 - signerMessageCount;
            int committedMessageCount = blindSideSlotCount - lengthNymVector;
            if(committedMessageCount < 0)
            {
                return false;
            }
            if(!BbsProofAlgorithm.AreIndicesValid(disclosed, signerMessageCount)
                || !BbsProofAlgorithm.AreIndicesValid(disclosedCommitted, committedMessageCount))
            {
                return false;
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsNymVerifyProof, CurveParameterSet.Bls12Curve381);

            string apiId = pseudonymCiphersuite.Identifier;

            //Decode the proof's G1 points and scalars and the pseudonym point
            //inside try/catch — any malformed slice returns false.
            G1Point? aBar = null;
            G1Point? bBar = null;
            G1Point? d = null;
            G1Point? pseudonymPoint = null;
            Scalar? eHat = null;
            Scalar? r1Hat = null;
            Scalar? r3Hat = null;
            Scalar? c = null;
            Scalar[]? mHats = null;
            try
            {
                aBar = G1Point.FromCanonical(proof.GetABarBytes(), CurveParameterSet.Bls12Curve381, pool);
                bBar = G1Point.FromCanonical(proof.GetBBarBytes(), CurveParameterSet.Bls12Curve381, pool);
                d = G1Point.FromCanonical(proof.GetDBytes(), CurveParameterSet.Bls12Curve381, pool);
                pseudonymPoint = G1Point.FromCanonical(pseudonym.GetPseudonymBytes(), CurveParameterSet.Bls12Curve381, pool);
                eHat = Scalar.FromCanonical(proof.GetEHatBytes(), CurveParameterSet.Bls12Curve381, pool);
                r1Hat = Scalar.FromCanonical(proof.GetR1HatBytes(), CurveParameterSet.Bls12Curve381, pool);
                r3Hat = Scalar.FromCanonical(proof.GetR3HatBytes(), CurveParameterSet.Bls12Curve381, pool);
                c = Scalar.FromCanonical(proof.GetChallengeBytes(), CurveParameterSet.Bls12Curve381, pool);

                mHats = new Scalar[u];
                for(int i = 0; i < u; i++)
                {
                    mHats[i] = Scalar.FromCanonical(proof.GetCommitmentBytes(i), CurveParameterSet.Bls12Curve381, pool);
                }
            }
            catch(ArgumentException)
            {
                aBar?.Dispose();
                bBar?.Dispose();
                d?.Dispose();
                pseudonymPoint?.Dispose();
                eHat?.Dispose();
                r1Hat?.Dispose();
                r3Hat?.Dispose();
                c?.Dispose();
                if(mHats is not null)
                {
                    for(int i = 0; i < mHats.Length; i++)
                    {
                        mHats[i]?.Dispose();
                    }
                }

                return false;
            }

            //Assigned inside the disposing try so a throw from any of these
            //allocations still releases everything already rented — including
            //the decoded proof components and the pseudonym point — via the
            //finally.
            ImmutableArray<Scalar> disclosedSignerScalars = [];
            ImmutableArray<Scalar> disclosedCommittedScalars = [];
            ImmutableArray<G1Point> generators = [];
            ImmutableArray<G1Point> blindGenerators = [];

            BbsProofInitResult? initResult = null;
            G1Point? uv = null;
            try
            {
                disclosedSignerScalars = BbsAlgorithm.MessagesToScalars(disclosedMessages, apiId, hashToScalar, pool);
                disclosedCommittedScalars = BbsAlgorithm.MessagesToScalars(disclosedCommittedMessages, apiId, hashToScalar, pool);
                generators = BbsAlgorithm.CreateGenerators(signerMessageCount + 1, apiId, expandMessage, g1HashToCurve, pool);
                blindGenerators = BbsAlgorithm.CreateGenerators(
                    blindSideSlotCount + 1,
                    BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                    expandMessage,
                    g1HashToCurve,
                    pool);

                try
                {
                    //octets_to_proof steps 6-8 plus the Section 3.3 pseudonym
                    //constraints: every G1 component must decode onto the curve,
                    //must not be the identity, and must lie in the prime-order
                    //subgroup (the pseudonym's identity/BP1 byte forms were
                    //already refused at BbsPseudonym intake; geometry and
                    //subgroup membership need the backend, so they gate here).
                    ReadOnlySpan<G1Point> validatedPoints = [aBar!, bBar!, d!, pseudonymPoint!];
                    foreach(G1Point validatedPoint in validatedPoints)
                    {
                        if(!validatedPoint.IsOnCurve(g1IsOnCurve) || validatedPoint.IsIdentity || !validatedPoint.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup))
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

                    //Combined generator vector and disclosed index remap, exactly
                    //mirroring the prover side.
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

                    int disclosedTotal = disclosed.Length + disclosedCommitted.Length;
                    int[] combinedDisclosed = new int[disclosedTotal];
                    Scalar[] disclosedScalars = new Scalar[disclosedTotal];
                    for(int i = 0; i < disclosed.Length; i++)
                    {
                        combinedDisclosed[i] = disclosed[i];
                        disclosedScalars[i] = disclosedSignerScalars[i];
                    }
                    for(int i = 0; i < disclosedCommitted.Length; i++)
                    {
                        combinedDisclosed[disclosed.Length + i] = disclosedCommitted[i] + signerMessageCount + 1;
                        disclosedScalars[disclosed.Length + i] = disclosedCommittedScalars[i];
                    }
                    int[] undisclosed = BbsProofAlgorithm.ComputeUndisclosedIndices(combinedDisclosed, totalMessageCount);

                    //CoreProofVerifyWithNym step 1: the declared nym-vector length
                    //rides the header into the domain.
                    (IMemoryOwner<byte> combinedHeaderOwner, int combinedHeaderLength) = BbsPseudonymAlgorithm.ComputeCombinedHeader(header.Bytes, lengthNymVector, pool);
                    using IMemoryOwner<byte> combinedHeader = combinedHeaderOwner;

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
                        combinedHeader.Memory[..combinedHeaderLength],
                        combinedDisclosed,
                        disclosedScalars,
                        undisclosed,
                        apiId,
                        hashToScalar,
                        g1Add,
                        g1MultiScalarMultiply,
                        pool);

                    //CoreProofVerifyWithNym step 3: recompute the announcement
                    //from the LAST N response scalars — those of the nym message
                    //slots — and the challenge.
                    uv = BbsPseudonymAlgorithm.PseudonymProofVerifyInit(
                        pseudonymPoint!,
                        mHats.AsSpan()[^lengthNymVector..],
                        c!,
                        contextId.Span,
                        apiId,
                        hashToScalar,
                        scalarAdd,
                        scalarMultiply,
                        scalarNegate,
                        g1HashToCurve,
                        g1MultiScalarMultiply,
                        pool);
                    if(uv is null)
                    {
                        return false;
                    }

                    //CoreProofVerifyWithNym steps 5-6: re-derive the challenge with
                    //the pseudonym and the recomputed announcement absorbed, and
                    //compare in fixed time.
                    using Scalar challenge = BbsPseudonymAlgorithm.CalculateChallengeWithPseudonym(
                        combinedDisclosed,
                        disclosedScalars,
                        initResult,
                        pseudonymPoint!,
                        uv,
                        contextId.Span,
                        presentationHeader.Bytes,
                        apiId,
                        hashToScalar,
                        pool);
                    if(!CryptographicOperations.FixedTimeEquals(challenge.AsReadOnlySpan(), c!.AsReadOnlySpan()))
                    {
                        return false;
                    }

                    //CoreProofVerifyWithNym step 7: e(Abar, W) == e(Bbar, BP2), the
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
                pseudonymPoint.Dispose();
                uv?.Dispose();
                eHat.Dispose();
                r1Hat.Dispose();
                r3Hat.Dispose();
                c.Dispose();
                for(int i = 0; i < mHats.Length; i++)
                {
                    mHats[i].Dispose();
                }
                foreach(Scalar scalar in disclosedSignerScalars)
                {
                    scalar.Dispose();
                }
                foreach(Scalar scalar in disclosedCommittedScalars)
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
