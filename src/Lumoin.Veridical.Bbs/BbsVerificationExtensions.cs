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
/// BBS+ verification extension on <see cref="BbsPublicKey"/>. Verify
/// is the verifier-side capability: a holder of the public key
/// checks that a signature was produced over the same header and
/// message vector by a holder of the corresponding secret key.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsVerificationExtensions
{
    extension(BbsPublicKey publicKey)
    {
        /// <summary>
        /// Verifies a BBS+ signature over <paramref name="header"/> and
        /// <paramref name="messages"/> against <paramref name="publicKey"/>
        /// per IETF Sections 3.5.2 (Verify) and 3.6.2 (CoreVerify).
        /// Returns <see langword="false"/> on any decode failure or
        /// ciphersuite mismatch; throws only on null arguments.
        /// </summary>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="header">Application-context bytes the signer bound into the signature.</param>
        /// <param name="messages">The message vector to verify against.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the signature point <c>A</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for the signature point <c>A</c>.</param>
        /// <param name="g2Add">Backend G2 addition.</param>
        /// <param name="g2ScalarMultiply">Backend G2 scalar multiplication.</param>
        /// <param name="g2IsOnCurve">Backend G2 on-curve validation for the public-key point <c>W</c>.</param>
        /// <param name="g2IsInPrimeOrderSubgroup">Backend G2 prime-order-subgroup validation for the public-key point <c>W</c>.</param>
        /// <param name="pairing">Backend optimal-ate pairing.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns><see langword="true"/> when the signature is valid; <see langword="false"/> otherwise.</returns>
        /// <remarks>
        /// <para>
        /// Uses the equivalent verification form <c>e(A, W + BP2·e) = e(B, BP2)</c>
        /// rather than the spec's <c>e(A, W) · e(A·e − B, BP2) = 1</c>:
        /// the two forms are algebraically equal but the equivalent
        /// form avoids one Fp12 multiplication and one G1 subtraction.
        /// </para>
        /// <para>
        /// Deserialization follows the spec's <c>octets_to_signature</c>
        /// (Section 4.2.4.3) and <c>octets_to_pubkey</c> (Section 4.2.4.6):
        /// the signature point <c>A</c> and the public key <c>W</c> must
        /// decode onto their curves, must not be the identity, and must lie
        /// in the prime-order subgroups; both curves have non-trivial
        /// cofactors, so on-curve membership alone does not imply subgroup
        /// membership.
        /// </para>
        /// </remarks>
        public bool Verify(
            BbsSignature signature,
            BbsHeader header,
            ReadOnlyMemory<BbsMessage> messages,
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
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(signature);
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

            if(publicKey.Ciphersuite != signature.Ciphersuite)
            {
                return false;
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsVerify, CurveParameterSet.Bls12Curve381);

            string apiId = publicKey.Ciphersuite.Identifier;
            int messageCount = messages.Length;

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

            ImmutableArray<Scalar> messageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);
            ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(messageCount + 1, apiId, expandMessage, g1HashToCurve, pool);

            try
            {
                try
                {
                    //octets_to_signature steps 5-7 (Section 4.2.4.3): A must decode onto
                    //the curve, must not be the identity, and must lie in the prime-order
                    //subgroup. The scalar e's canonicity (range and non-zero) is enforced
                    //at BbsSignature construction.
                    if(!a.IsOnCurve(g1IsOnCurve) || a.IsIdentity || !a.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup))
                    {
                        return false;
                    }

                    //octets_to_pubkey steps 2-4 (Section 4.2.4.6): W must decode onto
                    //the curve, must lie in the prime-order subgroup, and must not be
                    //the identity.
                    using G2Point w = G2Point.FromCanonical(publicKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                    if(!w.IsOnCurve(g2IsOnCurve) || !w.IsInPrimeOrderSubgroup(g2IsInPrimeOrderSubgroup) || w.IsIdentity)
                    {
                        return false;
                    }

                    G1Point q1 = generators[0];
                    ReadOnlySpan<G1Point> hPoints = generators.AsSpan()[1..];

                    using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, hPoints, header.Bytes, apiId, hashToScalar, pool);
                    using G1Point p1 = BbsP1Generator.GetForCiphersuite(publicKey.Ciphersuite, pool);
                    using G1Point b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars.AsSpan(), g1Add, g1MultiScalarMultiply, pool);

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
                    //object (off-curve, wrong subgroup). Mirrors VerifyProof's
                    //contract by returning false rather than propagating.
                    return false;
                }
            }
            finally
            {
                a.Dispose();
                e.Dispose();
                foreach(Scalar scalar in messageScalars)
                {
                    scalar.Dispose();
                }
                foreach(G1Point generator in generators)
                {
                    generator.Dispose();
                }
            }
        }
    }
}