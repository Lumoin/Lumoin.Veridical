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
/// BBS+ signing extension on <see cref="BbsSecretKey"/>. Sign is the
/// signer-side capability: a holder of the secret key produces a
/// signature over a header and message vector.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsSigningExtensions
{
    extension(BbsSecretKey secretKey)
    {
        /// <summary>
        /// Produces a BBS+ signature over <paramref name="header"/> and
        /// <paramref name="messages"/> under <paramref name="secretKey"/>,
        /// per IETF <c>draft-irtf-cfrg-bbs-signatures-10</c> Sections
        /// 3.5.1 (Sign) and 3.6.1 (CoreSign). Deterministic given the
        /// inputs.
        /// </summary>
        /// <param name="publicKey">The public key corresponding to <paramref name="secretKey"/>; required by the spec because <c>domain</c> includes PK.</param>
        /// <param name="header">Optional application-context bytes bound into the signature; may be empty.</param>
        /// <param name="messages">The message vector to sign.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarInvert">Backend scalar inverse.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (used during generator derivation).</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>A signature wrapping a pool-rented 80-byte buffer.</returns>
        /// <exception cref="ArgumentException">When <paramref name="publicKey"/>'s ciphersuite differs from <paramref name="secretKey"/>'s.</exception>
        public BbsSignature Sign(
            BbsPublicKey publicKey,
            BbsHeader header,
            ReadOnlyMemory<BbsMessage> messages,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarAddDelegate scalarAdd,
            ScalarInvertDelegate scalarInvert,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
            G1HashToCurveDelegate g1HashToCurve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(secretKey);
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1HashToCurve);
            ArgumentNullException.ThrowIfNull(pool);

            if(secretKey.Ciphersuite != publicKey.Ciphersuite)
            {
                throw new ArgumentException("BBS+ secret key and public key must share the same ciphersuite.", nameof(publicKey));
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsSign, CurveParameterSet.Bls12Curve381);

            string apiId = secretKey.Ciphersuite.Identifier;
            int messageCount = messages.Length;

            ImmutableArray<Scalar> messageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);
            ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(messageCount + 1, apiId, expandMessage, g1HashToCurve, pool);

            try
            {
                G1Point q1 = generators[0];
                ReadOnlySpan<G1Point> hPoints = generators.AsSpan()[1..];

                using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, hPoints, header.Bytes, apiId, hashToScalar, pool);
                using Scalar e = BbsAlgorithm.DeriveSigningScalar(secretKey, messageScalars.AsSpan(), domain, apiId, hashToScalar, pool);

                using G1Point p1 = BbsP1Generator.GetForCiphersuite(secretKey.Ciphersuite, pool);
                using G1Point b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars.AsSpan(), g1Add, g1MultiScalarMultiply, pool);

                //SK_plus_e = SK + e; invert; A = B · (1 / (SK + e)).
                using Scalar skScalar = Scalar.FromCanonical(secretKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                using Scalar skPlusE = skScalar.Add(e, scalarAdd, pool);
                using Scalar inverse = skPlusE.Invert(scalarInvert, pool);
                using G1Point a = b.ScalarMultiply(inverse, g1ScalarMultiply, pool);

                //Encode signature = A (48 bytes) || e (32 bytes).
                IMemoryOwner<byte> signatureOwner = pool.Rent(BbsSignature.SizeBytes);
                Span<byte> destination = signatureOwner.Memory.Span[..BbsSignature.SizeBytes];
                a.AsReadOnlySpan().CopyTo(destination[..BbsSignature.ASizeBytes]);
                e.AsReadOnlySpan().CopyTo(destination.Slice(BbsSignature.EOffset, BbsSignature.ESizeBytes));

                Tag signatureTag = ProviderInstrumentation.StampTag(
                    BbsSignature.GetAlgebraicTag(secretKey.Ciphersuite),
                    WellKnownBbsProviderIdentities.Library,
                    WellKnownBbsProviderIdentities.Crypto,
                    WellKnownBbsProviderIdentities.Class,
                    ProviderOperation.SignatureSign);
                return new BbsSignature(signatureOwner, signatureTag);
            }
            finally
            {
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