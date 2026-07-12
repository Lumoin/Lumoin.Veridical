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
/// Blind BBS signature verification on <see cref="BbsBlindSignature"/>.
/// VerifyBlindSign is the prover-side capability: after receiving a
/// blind signature the prover — the only party holding
/// <c>secret_prover_blind</c> and the committed messages — checks the
/// signature over the full message vector before relying on it.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsBlindVerificationExtensions
{
    extension(BbsBlindSignature signature)
    {
        /// <summary>
        /// Verifies a blind BBS signature against
        /// <paramref name="publicKey"/> over the full message vector per
        /// IETF <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section
        /// 4.2.2 (VerifyBlindSign), composing the core CoreVerify
        /// equation over the combined generator vector. Returns
        /// <see langword="false"/> on any decode failure or ciphersuite
        /// mismatch; throws only on null arguments.
        /// </summary>
        /// <param name="publicKey">The signer's public key.</param>
        /// <param name="header">Application-context bytes the signer bound into the signature.</param>
        /// <param name="messages">The FULL message vector: first the <paramref name="issuerMessageCount"/> signer-chosen messages, then the prover-committed messages, in commitment order.</param>
        /// <param name="issuerMessageCount">How many leading entries of <paramref name="messages"/> the signer chose (<c>issuer_known_messages_no</c>); the rest were committed by the prover.</param>
        /// <param name="secretProverBlind">The blinding factor returned by <c>Commit</c>, or <see langword="null"/> when the signature was produced without a commitment (the spec's zero default).</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
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
        /// <returns><see langword="true"/> when the blind signature is valid over the supplied vector and blinding factor; <see langword="false"/> otherwise.</returns>
        /// <remarks>
        /// <para>
        /// The scalar vector the pairing equation covers is
        /// <c>(issuer messages, secret_prover_blind, committed messages)</c>
        /// against the generators <c>(Q_1, H_1..H_L, Q_2, J_1..J_M)</c>:
        /// <c>secret_prover_blind</c> sits in the <c>Q_2</c> slot BETWEEN
        /// the two message families, matching CoreCommit's Pedersen
        /// pairing and B_calculate's commitment absorption. An absent
        /// blinding factor contributes <c>Q_2 * 0</c>, so <c>Q_2</c>
        /// participates in the domain either way.
        /// </para>
        /// <para>
        /// Uses the same equivalent pairing form as the core Verify:
        /// <c>e(A, W + BP2 * e) = e(B, BP2)</c>, compared with
        /// <c>FixedTimeEquals</c>.
        /// </para>
        /// </remarks>
        public bool VerifyBlindSign(
            BbsPublicKey publicKey,
            BbsHeader header,
            ReadOnlyMemory<BbsMessage> messages,
            int issuerMessageCount,
            Scalar? secretProverBlind,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
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
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
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

            if(issuerMessageCount < 0 || issuerMessageCount > messages.Length)
            {
                return false;
            }

            //The signature must carry the exact Blind BBS Interface of the
            //key's base suite — a pseudonym-Interface signature must be
            //refused here even though the wire shape matches, because every
            //DST differs.
            BbsCiphersuite blindCiphersuite = BbsBlindAlgorithm.GetBlindInterface(publicKey.Ciphersuite);
            if(signature.Ciphersuite != blindCiphersuite)
            {
                return false;
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsBlindVerify, CurveParameterSet.Bls12Curve381);

            string apiId = blindCiphersuite.Identifier;
            int totalMessageCount = messages.Length;
            int committedMessageCount = totalMessageCount - issuerMessageCount;

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

                return false;
            }

            //Assigned inside the disposing try so a throw from any of these
            //allocations still releases everything already rented — including
            //the decoded (A, e) — via the finally.
            ImmutableArray<Scalar> messageScalars = [];
            ImmutableArray<G1Point> generators = [];
            ImmutableArray<G1Point> blindGenerators = [];

            Scalar? zeroBlind = null;
            try
            {
                messageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);
                generators = BbsAlgorithm.CreateGenerators(issuerMessageCount + 1, apiId, expandMessage, g1HashToCurve, pool);
                blindGenerators = BbsAlgorithm.CreateGenerators(
                    committedMessageCount + 1,
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
                        return false;
                    }

                    //octets_to_pubkey steps 2-4: W must decode onto the curve,
                    //must lie in the prime-order subgroup, and must not be the
                    //identity.
                    using G2Point w = G2Point.FromCanonical(publicKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                    if(!w.IsOnCurve(g2IsOnCurve) || !w.IsInPrimeOrderSubgroup(g2IsInPrimeOrderSubgroup) || w.IsIdentity)
                    {
                        return false;
                    }

                    if(secretProverBlind is null)
                    {
                        //The spec's zero default: Q_2 * 0 contributes the identity
                        //but keeps the generator/scalar vectors aligned.
                        zeroBlind = Scalar.FromCanonical(stackalloc byte[Scalar.SizeBytes], CurveParameterSet.Bls12Curve381, pool);
                    }
                    Scalar blindScalar = secretProverBlind ?? zeroBlind!;

                    G1Point q1 = generators[0];

                    //Combined generator vector (H_1..H_L, Q_2, J_1..J_M) paired
                    //with (issuer messages, secret_prover_blind, committed
                    //messages); the same combined list feeds the domain.
                    G1Point[] combinedHPoints = new G1Point[totalMessageCount + 1];
                    Scalar[] combinedScalars = new Scalar[totalMessageCount + 1];
                    for(int i = 0; i < issuerMessageCount; i++)
                    {
                        combinedHPoints[i] = generators[1 + i];
                        combinedScalars[i] = messageScalars[i];
                    }
                    combinedHPoints[issuerMessageCount] = blindGenerators[0];
                    combinedScalars[issuerMessageCount] = blindScalar;
                    for(int i = 0; i < committedMessageCount; i++)
                    {
                        combinedHPoints[issuerMessageCount + 1 + i] = blindGenerators[1 + i];
                        combinedScalars[issuerMessageCount + 1 + i] = messageScalars[issuerMessageCount + i];
                    }

                    using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, combinedHPoints, header.Bytes, apiId, hashToScalar, pool);
                    using G1Point p1 = BbsP1Generator.GetForCiphersuite(publicKey.Ciphersuite, pool);
                    using G1Point b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, combinedHPoints, combinedScalars, g1Add, g1MultiScalarMultiply, pool);

                    using G2Point bp2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, pool);

                    //W + BP2 · e.
                    using G2Point bp2TimesE = bp2.ScalarMultiply(e, g2ScalarMultiply, pool);
                    using G2Point pairingRhsG2 = w.Add(bp2TimesE, g2Add, pool);

                    //pairing(A, W + BP2·e) versus pairing(B, BP2).
                    using Fp12Element lhs = a.PairWith(pairingRhsG2, pairing, pool);
                    using Fp12Element rhs = b.PairWith(bp2, pairing, pool);

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
                a.Dispose();
                e.Dispose();
                zeroBlind?.Dispose();
                foreach(Scalar scalar in messageScalars)
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
