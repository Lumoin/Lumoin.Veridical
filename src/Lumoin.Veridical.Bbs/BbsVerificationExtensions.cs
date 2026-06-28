using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

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
        /// <param name="g2Add">Backend G2 addition.</param>
        /// <param name="g2ScalarMultiply">Backend G2 scalar multiplication.</param>
        /// <param name="pairing">Backend optimal-ate pairing.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns><see langword="true"/> when the signature is valid; <see langword="false"/> otherwise.</returns>
        /// <remarks>
        /// Uses the equivalent verification form <c>e(A, W + BP2·e) = e(B, BP2)</c>
        /// rather than the spec's <c>e(A, W) · e(A·e − B, BP2) = 1</c>:
        /// the two forms are algebraically equal but the equivalent
        /// form avoids one Fp12 multiplication and one G1 subtraction.
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
            G2AddDelegate g2Add,
            G2ScalarMultiplyDelegate g2ScalarMultiply,
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
            ArgumentNullException.ThrowIfNull(g2Add);
            ArgumentNullException.ThrowIfNull(g2ScalarMultiply);
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
                    G1Point q1 = generators[0];
                    ReadOnlySpan<G1Point> hPoints = generators.AsSpan()[1..];

                    using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, hPoints, header.Bytes, apiId, hashToScalar, pool);
                    using G1Point p1 = BbsP1Generator.GetForCiphersuite(publicKey.Ciphersuite, pool);
                    using G1Point b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars.AsSpan(), g1Add, g1MultiScalarMultiply, pool);

                    //W = decode publicKey as G2 point.
                    using G2Point w = G2Point.FromCanonical(publicKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                    using G2Point bp2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, pool);

                    //W + BP2 · e.
                    using G2Point bp2TimesE = bp2.ScalarMultiply(e, g2ScalarMultiply, pool);
                    using G2Point pairingRhsG2 = w.Add(bp2TimesE, g2Add, pool);

                    //pairing(A, W + BP2·e) versus pairing(B, BP2).
                    using Fp12Element lhs = a.PairWith(pairingRhsG2, pairing, pool);
                    using Fp12Element rhs = b.PairWith(bp2, pairing, pool);

                    return lhs.AsReadOnlySpan().SequenceEqual(rhs.AsReadOnlySpan());
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