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
/// Blind BBS signing extension on <see cref="BbsSecretKey"/>. BlindSign
/// is the signer-side capability: a holder of the secret key produces a
/// signature over a header, its own message vector, and a
/// prover-supplied commitment whose committed messages the signer never
/// learns.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsBlindSigningExtensions
{
    private static readonly ProviderOperation BlindSignOperation = new("BbsBlindSign");


    extension(BbsSecretKey secretKey)
    {
        /// <summary>
        /// Produces a blind BBS signature over <paramref name="header"/>,
        /// <paramref name="messages"/>, and (when supplied) the prover's
        /// <paramref name="commitmentWithProof"/>, per IETF
        /// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Sections 4.2.1
        /// (BlindSign), 5.1 (B_calculate), and 4.3.3 (FinalizeBlindSign).
        /// Deterministic given the inputs.
        /// </summary>
        /// <param name="publicKey">The public key corresponding to <paramref name="secretKey"/>; required because <c>domain</c> includes PK.</param>
        /// <param name="commitmentWithProof">The prover's commitment-with-proof from <c>Commit</c>, or <see langword="null"/> when the prover commits to nothing (the spec's empty-string default; the commitment slot in <c>B</c> is then the identity).</param>
        /// <param name="header">Optional application-context bytes bound into the signature; may be empty.</param>
        /// <param name="messages">The signer-chosen message vector; may be empty.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarNegate">Backend scalar negation (commitment-proof verification).</param>
        /// <param name="scalarInvert">Backend scalar inverse.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the commitment point <c>C</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for <c>C</c>.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>A blind signature wrapping a pool-rented 80-byte buffer, tagged with the Blind BBS Interface of the key's ciphersuite.</returns>
        /// <exception cref="ArgumentException">When <paramref name="publicKey"/>'s ciphersuite differs from <paramref name="secretKey"/>'s; when <paramref name="commitmentWithProof"/> belongs to a different base hash suite; or when the commitment fails validation (invalid point geometry or a failing Schnorr proof of opening) — the signer MUST refuse to sign over an unproven commitment.</exception>
        /// <remarks>
        /// The domain is computed over the combined generator vector
        /// <c>(Q_1, H_1..H_L, Q_2, J_1..J_M)</c> — <c>Q_2</c> is included
        /// even when no messages are committed — and the signed point is
        /// <c>B = P1 + Q_1 * domain + sum_i H_i * msg_i + commitment</c>,
        /// so a verifier recomputing the core CoreVerify equation over the
        /// combined generators accepts the signature once the prover
        /// supplies <c>secret_prover_blind</c> and the committed messages.
        /// Both <c>L = 0</c> and <c>M = 0</c> are valid.
        /// </remarks>
        public BbsBlindSignature BlindSign(
            BbsPublicKey publicKey,
            BbsCommitmentWithProof? commitmentWithProof,
            BbsHeader header,
            ReadOnlyMemory<BbsMessage> messages,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarAddDelegate scalarAdd,
            ScalarNegateDelegate scalarNegate,
            ScalarInvertDelegate scalarInvert,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
            G1HashToCurveDelegate g1HashToCurve,
            G1IsOnCurveDelegate g1IsOnCurve,
            G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(secretKey);
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarNegate);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1HashToCurve);
            ArgumentNullException.ThrowIfNull(g1IsOnCurve);
            ArgumentNullException.ThrowIfNull(g1IsInPrimeOrderSubgroup);
            ArgumentNullException.ThrowIfNull(pool);

            if(secretKey.Ciphersuite != publicKey.Ciphersuite)
            {
                throw new ArgumentException("BBS+ secret key and public key must share the same ciphersuite.", nameof(publicKey));
            }

            //Keys carry the base hash suite; blind containers carry the
            //interface-scoped one. The comparison must go through the
            //base-suite mapping — naive equality between them is always false.
            BbsCiphersuite blindCiphersuite = BbsBlindAlgorithm.GetBlindInterface(secretKey.Ciphersuite);
            if(commitmentWithProof is not null && commitmentWithProof.Ciphersuite != blindCiphersuite)
            {
                throw new ArgumentException("BBS+ commitment-with-proof must be produced under the Blind BBS Interface of the signing key's ciphersuite.", nameof(commitmentWithProof));
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsBlindSign, CurveParameterSet.Bls12Curve381);

            string apiId = blindCiphersuite.Identifier;
            int signerMessageCount = messages.Length;
            int committedMessageCount = commitmentWithProof?.CommittedMessageCount ?? 0;

            //Assigned inside the disposing try so a throw from any of these
            //allocations still releases everything already rented via the
            //finally.
            ImmutableArray<G1Point> generators = [];
            ImmutableArray<G1Point> blindGenerators = [];
            ImmutableArray<Scalar> messageScalars = [];

            G1Point? b = null;
            try
            {
                generators = BbsAlgorithm.CreateGenerators(signerMessageCount + 1, apiId, expandMessage, g1HashToCurve, pool);
                blindGenerators = BbsAlgorithm.CreateGenerators(
                    committedMessageCount + 1,
                    BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                    expandMessage,
                    g1HashToCurve,
                    pool);
                messageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);

                G1Point q1 = generators[0];
                ReadOnlySpan<G1Point> hPoints = generators.AsSpan()[1..];

                //FinalizeBlindSign step 1: domain over the combined H-list
                //(H_1..H_L, Q_2, J_1..J_M) — Q_2 IS in the domain input.
                G1Point[] domainHPoints = new G1Point[signerMessageCount + committedMessageCount + 1];
                for(int i = 0; i < signerMessageCount; i++)
                {
                    domainHPoints[i] = generators[1 + i];
                }
                for(int i = 0; i < blindGenerators.Length; i++)
                {
                    domainHPoints[signerMessageCount + i] = blindGenerators[i];
                }
                using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, domainHPoints, header.Bytes, apiId, hashToScalar, pool);

                //deserialize_and_validate_commit: the signer MUST refuse to
                //sign when the proof of the commitment's opening fails.
                {
                    using G1Point commitment = BbsBlindAlgorithm.DeserializeAndValidateCommit(
                        commitmentWithProof,
                        blindGenerators.AsSpan(),
                        apiId,
                        hashToScalar,
                        scalarNegate,
                        g1MultiScalarMultiply,
                        g1IsOnCurve,
                        g1IsInPrimeOrderSubgroup,
                        pool)
                        ?? throw new ArgumentException("BBS+ commitment-with-proof failed validation: the commitment point or its proof of opening is invalid.", nameof(commitmentWithProof));

                    //B_calculate: B = P1 + Q_1 * domain + sum_i H_i * msg_i + commitment.
                    using G1Point p1 = BbsP1Generator.GetForCiphersuite(secretKey.Ciphersuite, pool);
                    if(commitmentWithProof is null)
                    {
                        //Absent commitment: the identity default contributes nothing,
                        //so B omits the commitment term rather than adding O.
                        b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars.AsSpan(), g1Add, g1MultiScalarMultiply, pool);
                    }
                    else
                    {
                        using G1Point bWithoutCommitment = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars.AsSpan(), g1Add, g1MultiScalarMultiply, pool);
                        b = bWithoutCommitment.Add(commitment, g1Add, pool);
                    }
                }

                if(b.IsIdentity)
                {
                    throw new ArgumentException("The computed blind-signature point B must not be the identity.", nameof(messages));
                }

                //FinalizeBlindSign steps 2-4: e = hash_to_scalar(serialize((SK, B,
                //domain)), api_id || "H2S_"); A = B * (1 / (SK + e)).
                using Scalar e = BbsBlindAlgorithm.DeriveBlindSigningScalar(secretKey, b, domain, apiId, hashToScalar, pool);
                using Scalar skScalar = Scalar.FromCanonical(secretKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                using Scalar skPlusE = skScalar.Add(e, scalarAdd, pool);
                using Scalar inverse = skPlusE.Invert(scalarInvert, pool);
                using G1Point a = b.ScalarMultiply(inverse, g1ScalarMultiply, pool);

                //Encode blind signature = A (48 bytes) || e (32 bytes).
                IMemoryOwner<byte> signatureOwner = pool.Rent(BbsBlindSignature.SizeBytes);
                try
                {
                    Span<byte> destination = signatureOwner.Memory.Span[..BbsBlindSignature.SizeBytes];
                    a.AsReadOnlySpan().CopyTo(destination[..BbsBlindSignature.ASizeBytes]);
                    e.AsReadOnlySpan().CopyTo(destination.Slice(BbsBlindSignature.EOffset, BbsBlindSignature.ESizeBytes));

                    Tag signatureTag = ProviderInstrumentation.StampTag(
                        BbsBlindSignature.GetAlgebraicTag(blindCiphersuite),
                        WellKnownBbsProviderIdentities.Library,
                        WellKnownBbsProviderIdentities.Crypto,
                        WellKnownBbsProviderIdentities.Class,
                        BlindSignOperation);

                    return new BbsBlindSignature(signatureOwner, signatureTag);
                }
                catch
                {
                    signatureOwner.Dispose();
                    throw;
                }
            }
            finally
            {
                b?.Dispose();
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
