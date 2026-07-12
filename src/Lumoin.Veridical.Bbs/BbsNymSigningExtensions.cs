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
/// Per-verifier-pseudonym blind signing extension on
/// <see cref="BbsSecretKey"/>. BlindSignWithNym is the signer-side
/// capability: a holder of the secret key produces a signature over a
/// header, its own message vector, and a prover-supplied commitment
/// carrying the prover's nym scalars, blindly adding its own
/// <c>signer_nym_entropy</c> onto the last nym slot so neither party
/// alone controls the final <c>nym_secrets</c>.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsNymSigningExtensions
{
    private static readonly ProviderOperation BlindSignWithNymOperation = new("BbsNymBlindSign");


    extension(BbsSecretKey secretKey)
    {
        /// <summary>
        /// Produces a pseudonym-Interface blind BBS signature over
        /// <paramref name="header"/>, <paramref name="messages"/>, and the
        /// prover's <paramref name="commitmentWithProof"/>, folding
        /// <paramref name="signerNymEntropy"/> onto the last committed
        /// (nym) slot, per IETF
        /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section
        /// 6.1.2 (BlindSignWithNym). Deterministic given the inputs.
        /// </summary>
        /// <param name="publicKey">The public key corresponding to <paramref name="secretKey"/>; required because <c>domain</c> includes PK.</param>
        /// <param name="commitmentWithProof">The prover's commitment-with-proof from <c>CommitWithNym</c>. Required: the pseudonym Interface has no commitment-free issuance, because the prover's nym scalars only ever reach the signer inside a commitment.</param>
        /// <param name="lengthNymVector">The prover-declared nym-vector length <c>N</c>, conveyed alongside the commitment. Folded into <c>combined_header = header || I2OSP(N, 8)</c> so the signature certifies exactly this many nym secrets (the draft's Sybil-resistance binding, Section 10.2).</param>
        /// <param name="signerNymEntropy">The signer's contribution to the last nym secret: <c>B += J_last * signer_nym_entropy</c> effects <c>nym_secrets[-1] = prover_nyms[-1] + signer_nym_entropy</c> inside the commitment. Fresh per prover; MAY be reused on reissue to the same prover to preserve their pseudonymous identity (Section 6.1.2).</param>
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
        /// <returns>A blind signature wrapping a pool-rented 80-byte buffer, tagged with the pseudonym Interface of the key's ciphersuite.</returns>
        /// <exception cref="ArgumentException">When <paramref name="publicKey"/>'s ciphersuite differs from <paramref name="secretKey"/>'s; when <paramref name="commitmentWithProof"/> is not tagged with the key's pseudonym Interface; when <paramref name="lengthNymVector"/> is not in <c>[1, M]</c> for the commitment's <c>M</c> committed slots; or when the commitment fails validation — the signer MUST refuse to sign over an unproven commitment.</exception>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="lengthNymVector"/> is negative.</exception>
        /// <remarks>
        /// The domain is computed over the combined generator vector
        /// <c>(Q_1, H_1..H_L, Q_2, J_1..J_M)</c> with the
        /// length-suffixed <c>combined_header</c>, and the signed point is
        /// <c>B = P1 + Q_1 * domain + sum_i H_i * msg_i + commitment
        /// + J_M * signer_nym_entropy</c>. The <c>e</c> scalar is derived
        /// over <c>serialize((SK, B))</c> — the form the draft's own test
        /// vectors pin byte-for-byte (see
        /// <see cref="BbsBlindAlgorithm.DeriveBlindSigningScalar"/> for the
        /// divergence from the blind -03 text this reflects).
        /// </remarks>
        public BbsBlindSignature BlindSignWithNym(
            BbsPublicKey publicKey,
            BbsCommitmentWithProof commitmentWithProof,
            int lengthNymVector,
            Scalar signerNymEntropy,
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
            ArgumentNullException.ThrowIfNull(commitmentWithProof);
            ArgumentNullException.ThrowIfNull(signerNymEntropy);
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
            ArgumentOutOfRangeException.ThrowIfNegative(lengthNymVector);

            if(secretKey.Ciphersuite != publicKey.Ciphersuite)
            {
                throw new ArgumentException("BBS+ secret key and public key must share the same ciphersuite.", nameof(publicKey));
            }

            //Keys carry the base hash suite; nym containers carry the
            //interface-scoped one. The comparison must go through the
            //pseudonym-interface mapping — naive equality between them is
            //always false, and a blind-Interface commitment must be refused
            //here because its challenge was bound under a different api_id.
            BbsCiphersuite pseudonymCiphersuite = BbsPseudonymAlgorithm.GetPseudonymInterface(secretKey.Ciphersuite);
            if(commitmentWithProof.Ciphersuite != pseudonymCiphersuite)
            {
                throw new ArgumentException("BBS+ commitment-with-proof must be produced under the pseudonym Interface of the signing key's ciphersuite.", nameof(commitmentWithProof));
            }

            //The commitment's committed slots are (committed messages, prover_nyms):
            //the declared nym-vector length must fit inside them, and at least one
            //nym slot must exist for the entropy addition to land on.
            int committedScalarCount = commitmentWithProof.CommittedMessageCount;
            if(lengthNymVector < 1 || lengthNymVector > committedScalarCount)
            {
                throw new ArgumentException(
                    $"length_nym_vector must be in [1, {committedScalarCount}] for a commitment with {committedScalarCount} committed slots; received {lengthNymVector}.",
                    nameof(lengthNymVector));
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsNymBlindSign, CurveParameterSet.Bls12Curve381);

            string apiId = pseudonymCiphersuite.Identifier;
            int signerMessageCount = messages.Length;

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
                    committedScalarCount + 1,
                    BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                    expandMessage,
                    g1HashToCurve,
                    pool);
                messageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);

                G1Point q1 = generators[0];
                ReadOnlySpan<G1Point> hPoints = generators.AsSpan()[1..];

                //BlindSignWithNym step 9: the declared nym-vector length rides the
                //header into the domain, binding N into the signature.
                (IMemoryOwner<byte> combinedHeaderOwner, int combinedHeaderLength) = BbsPseudonymAlgorithm.ComputeCombinedHeader(header.Bytes, lengthNymVector, pool);
                using IMemoryOwner<byte> combinedHeader = combinedHeaderOwner;

                //FinalizeBlindSign step 1: domain over the combined H-list
                //(H_1..H_L, Q_2, J_1..J_M) — Q_2 IS in the domain input.
                G1Point[] domainHPoints = new G1Point[signerMessageCount + committedScalarCount + 1];
                for(int i = 0; i < signerMessageCount; i++)
                {
                    domainHPoints[i] = generators[1 + i];
                }
                for(int i = 0; i < blindGenerators.Length; i++)
                {
                    domainHPoints[signerMessageCount + i] = blindGenerators[i];
                }
                using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, domainHPoints, combinedHeader.Memory[..combinedHeaderLength], apiId, hashToScalar, pool);

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
                    using G1Point bWithoutCommitment = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars.AsSpan(), g1Add, g1MultiScalarMultiply, pool);
                    using G1Point bWithCommitment = bWithoutCommitment.Add(commitment, g1Add, pool);

                    //BlindSignWithNym step 8: B += J_last * signer_nym_entropy. The
                    //last blind generator carries the last prover_nym, so this
                    //effects nym_secrets[-1] = prover_nyms[-1] + signer_nym_entropy
                    //inside the signed commitment without the signer ever seeing
                    //the prover's scalar.
                    using G1Point entropyTerm = blindGenerators[^1].ScalarMultiply(signerNymEntropy, g1ScalarMultiply, pool);
                    b = bWithCommitment.Add(entropyTerm, g1Add, pool);
                }

                if(b.IsIdentity)
                {
                    throw new ArgumentException("The computed blind-signature point B must not be the identity.", nameof(messages));
                }

                //FinalizeBlindSign steps 2-4 in the vector-pinned form:
                //e = hash_to_scalar(serialize((SK, B)), api_id || "H2S_");
                //A = B * (1 / (SK + e)).
                using Scalar e = BbsBlindAlgorithm.DeriveBlindSigningScalar(secretKey, b, domain: null, apiId, hashToScalar, pool);
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
                        BbsBlindSignature.GetAlgebraicTag(pseudonymCiphersuite),
                        WellKnownBbsProviderIdentities.Library,
                        WellKnownBbsProviderIdentities.Crypto,
                        WellKnownBbsProviderIdentities.Class,
                        BlindSignWithNymOperation);

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
