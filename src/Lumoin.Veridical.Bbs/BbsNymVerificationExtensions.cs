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
/// Per-verifier-pseudonym signature finalization on
/// <see cref="BbsBlindSignature"/>. VerifyFinalizeWithNym is the
/// prover-side capability: after receiving a pseudonym-Interface blind
/// signature the prover — the only party holding
/// <c>secret_prover_blind</c>, the committed messages, and the
/// <c>prover_nyms</c> — finalizes its <c>nym_secrets</c> by folding in
/// the signer's entropy and checks the signature over the full message
/// vector before relying on it.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsNymVerificationExtensions
{
    extension(BbsBlindSignature signature)
    {
        /// <summary>
        /// Finalizes the prover's <c>nym_secrets</c>
        /// (<c>nym_secrets[-1] = prover_nyms[-1] + signer_nym_entropy</c>)
        /// and verifies the pseudonym-Interface blind signature against
        /// <paramref name="publicKey"/> over the full message vector, per
        /// IETF <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>
        /// Section 6.1.3 (VerifyFinalizeWithNym). Returns
        /// <see langword="null"/> on any decode failure, ciphersuite
        /// mismatch, or cryptographic failure; throws only on null or
        /// structurally invalid arguments.
        /// </summary>
        /// <param name="publicKey">The signer's public key.</param>
        /// <param name="header">Application-context bytes the signer bound into the signature (without the length suffix — the nym-vector length is re-derived from <paramref name="proverNyms"/> and folded in here, so a signer that certified a different length fails verification).</param>
        /// <param name="messages">The signer-chosen message vector, in signing order.</param>
        /// <param name="committedMessages">The prover-committed messages, in commitment order.</param>
        /// <param name="proverNyms">The prover's secret nym scalar vector, exactly as committed; at least one entry.</param>
        /// <param name="signerNymEntropy">The signer's entropy scalar returned alongside the signature.</param>
        /// <param name="secretProverBlind">The blinding factor returned by <c>CommitWithNym</c>.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition (the entropy fold).</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the signature point <c>A</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for <c>A</c>.</param>
        /// <param name="g2Add">Backend G2 addition.</param>
        /// <param name="g2ScalarMultiply">Backend G2 scalar multiplication.</param>
        /// <param name="g2IsOnCurve">Backend G2 on-curve validation for the public-key point <c>W</c>.</param>
        /// <param name="g2IsInPrimeOrderSubgroup">Backend G2 prime-order-subgroup validation for <c>W</c>.</param>
        /// <param name="pairing">Backend optimal-ate pairing.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>The finalized <c>nym_secrets</c> vector as caller-owned pooled scalars when the signature verifies; <see langword="null"/> otherwise. The prover keeps these secret — they are the pseudonym preimage and are never disclosed.</returns>
        /// <exception cref="ArgumentException">When <paramref name="proverNyms"/> is empty.</exception>
        /// <remarks>
        /// The scalar vector the pairing equation covers is
        /// <c>(signer messages, secret_prover_blind, committed messages,
        /// nym_secrets)</c> against the generators
        /// <c>(Q_1, H_1..H_L, Q_2, J_1..J_M)</c>: the finalized nym
        /// secrets occupy the LAST slots, matching the commitment layout
        /// and the entropy fold <c>BlindSignWithNym</c> applied to
        /// <c>B</c>. Uses the same equivalent pairing form as the core
        /// Verify: <c>e(A, W + BP2 * e) = e(B, BP2)</c>, compared with
        /// <c>FixedTimeEquals</c>.
        /// </remarks>
        [SuppressMessage("Reliability", "CA2000", Justification = "The nym_secrets scalars transfer ownership to the caller on success; every failure path disposes them through DisposeAll before returning null.")]
        public Scalar[]? VerifyFinalizeWithNym(
            BbsPublicKey publicKey,
            BbsHeader header,
            ReadOnlyMemory<BbsMessage> messages,
            ReadOnlyMemory<BbsMessage> committedMessages,
            ReadOnlyMemory<Scalar> proverNyms,
            Scalar signerNymEntropy,
            Scalar secretProverBlind,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarAddDelegate scalarAdd,
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
            ArgumentNullException.ThrowIfNull(signature);
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(signerNymEntropy);
            ArgumentNullException.ThrowIfNull(secretProverBlind);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarAdd);
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

            if(proverNyms.IsEmpty)
            {
                throw new ArgumentException("VerifyFinalizeWithNym requires at least one prover_nym scalar.", nameof(proverNyms));
            }

            //The signature must carry the exact pseudonym Interface of the key's
            //base suite — a blind-Interface signature must be refused here even
            //though the wire shape matches, because every DST differs.
            BbsCiphersuite pseudonymCiphersuite = BbsPseudonymAlgorithm.GetPseudonymInterface(publicKey.Ciphersuite);
            if(signature.Ciphersuite != pseudonymCiphersuite)
            {
                return null;
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsNymVerifyFinalize, CurveParameterSet.Bls12Curve381);

            string apiId = pseudonymCiphersuite.Identifier;
            int signerMessageCount = messages.Length;
            int committedMessageCount = committedMessages.Length;
            int nymCount = proverNyms.Length;
            int committedScalarCount = committedMessageCount + nymCount;

            //Finalization: nym_secrets = prover_nyms with the signer's entropy
            //folded onto the LAST element in the scalar field.
            Scalar[] nymSecrets = new Scalar[nymCount];
            try
            {
                for(int i = 0; i < nymCount - 1; i++)
                {
                    nymSecrets[i] = Scalar.FromCanonical(proverNyms.Span[i].AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                }
                nymSecrets[nymCount - 1] = proverNyms.Span[nymCount - 1].Add(signerNymEntropy, scalarAdd, pool);
            }
            catch
            {
                DisposeAll(nymSecrets);
                throw;
            }

            G1Point? a = null;
            Scalar? e = null;
            try
            {
                a = G1Point.FromCanonical(signature.GetABytes(), CurveParameterSet.Bls12Curve381, pool);
                e = Scalar.FromCanonical(signature.GetEBytes(), CurveParameterSet.Bls12Curve381, pool);
            }
            catch(ArgumentException)
            {
                a?.Dispose();
                e?.Dispose();
                DisposeAll(nymSecrets);

                return null;
            }

            //Assigned inside the disposing try so a throw from any of these
            //allocations still releases everything already rented — including
            //the nym_secrets and the decoded (A, e) — via the finally.
            ImmutableArray<Scalar> signerMessageScalars = [];
            ImmutableArray<Scalar> committedMessageScalars = [];
            ImmutableArray<G1Point> generators = [];
            ImmutableArray<G1Point> blindGenerators = [];

            bool valid = false;
            try
            {
                signerMessageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);
                committedMessageScalars = BbsAlgorithm.MessagesToScalars(committedMessages, apiId, hashToScalar, pool);
                generators = BbsAlgorithm.CreateGenerators(signerMessageCount + 1, apiId, expandMessage, g1HashToCurve, pool);
                blindGenerators = BbsAlgorithm.CreateGenerators(
                    committedScalarCount + 1,
                    BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                    expandMessage,
                    g1HashToCurve,
                    pool);

                try
                {
                    //octets_to_signature steps 5-7: A must decode onto the curve,
                    //must not be the identity, and must lie in the prime-order
                    //subgroup. The scalar e's canonicity is enforced at
                    //BbsBlindSignature construction.
                    if(!a.IsOnCurve(g1IsOnCurve) || a.IsIdentity || !a.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup))
                    {
                        return null;
                    }

                    //octets_to_pubkey steps 2-4: W must decode onto the curve,
                    //must lie in the prime-order subgroup, and must not be the
                    //identity.
                    using G2Point w = G2Point.FromCanonical(publicKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                    if(!w.IsOnCurve(g2IsOnCurve) || !w.IsInPrimeOrderSubgroup(g2IsInPrimeOrderSubgroup) || w.IsIdentity)
                    {
                        return null;
                    }

                    G1Point q1 = generators[0];

                    //Combined generator vector (H_1..H_L, Q_2, J_1..J_M) paired
                    //with (signer messages, secret_prover_blind, committed
                    //messages, nym_secrets); the same combined list feeds the
                    //domain.
                    int totalScalarCount = signerMessageCount + 1 + committedScalarCount;
                    G1Point[] combinedHPoints = new G1Point[totalScalarCount];
                    Scalar[] combinedScalars = new Scalar[totalScalarCount];
                    for(int i = 0; i < signerMessageCount; i++)
                    {
                        combinedHPoints[i] = generators[1 + i];
                        combinedScalars[i] = signerMessageScalars[i];
                    }
                    combinedHPoints[signerMessageCount] = blindGenerators[0];
                    combinedScalars[signerMessageCount] = secretProverBlind;
                    for(int i = 0; i < committedMessageCount; i++)
                    {
                        combinedHPoints[signerMessageCount + 1 + i] = blindGenerators[1 + i];
                        combinedScalars[signerMessageCount + 1 + i] = committedMessageScalars[i];
                    }
                    for(int i = 0; i < nymCount; i++)
                    {
                        combinedHPoints[signerMessageCount + 1 + committedMessageCount + i] = blindGenerators[1 + committedMessageCount + i];
                        combinedScalars[signerMessageCount + 1 + committedMessageCount + i] = nymSecrets[i];
                    }

                    //VerifyFinalizeWithNym step 5: the nym-vector length rides the
                    //header into the domain — the Sybil-resistance binding.
                    (IMemoryOwner<byte> combinedHeaderOwner, int combinedHeaderLength) = BbsPseudonymAlgorithm.ComputeCombinedHeader(header.Bytes, nymCount, pool);
                    using IMemoryOwner<byte> combinedHeader = combinedHeaderOwner;

                    using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, combinedHPoints, combinedHeader.Memory[..combinedHeaderLength], apiId, hashToScalar, pool);
                    using G1Point p1 = BbsP1Generator.GetForCiphersuite(publicKey.Ciphersuite, pool);
                    using G1Point b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, combinedHPoints, combinedScalars, g1Add, g1MultiScalarMultiply, pool);

                    using G2Point bp2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, pool);

                    //W + BP2 · e.
                    using G2Point bp2TimesE = bp2.ScalarMultiply(e, g2ScalarMultiply, pool);
                    using G2Point pairingRhsG2 = w.Add(bp2TimesE, g2Add, pool);

                    //pairing(A, W + BP2·e) versus pairing(B, BP2).
                    using Fp12Element lhs = a.PairWith(pairingRhsG2, pairing, pool);
                    using Fp12Element rhs = b.PairWith(bp2, pairing, pool);

                    valid = CryptographicOperations.FixedTimeEquals(lhs.AsReadOnlySpan(), rhs.AsReadOnlySpan());

                    return valid ? nymSecrets : null;
                }
                catch(InvalidOperationException)
                {
                    //Backend decode failures during MSM/pairing — the bytes
                    //decoded as length-valid but are not a valid algebraic
                    //object. Mirrors the core verify surfaces' contract by
                    //returning null rather than propagating.
                    return null;
                }
            }
            finally
            {
                if(!valid)
                {
                    DisposeAll(nymSecrets);
                }
                a.Dispose();
                e.Dispose();
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


    private static void DisposeAll(Scalar?[] scalars)
    {
        for(int i = 0; i < scalars.Length; i++)
        {
            scalars[i]?.Dispose();
        }
    }
}
