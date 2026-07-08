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
/// BBS+ selective-disclosure proof generation extension on
/// <see cref="BbsSignature"/>. GenerateProof is the Prover-side
/// capability: a holder of a valid signature constructs a
/// zero-knowledge proof of that knowledge, revealing only a chosen
/// subset of the signed messages.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsProofGenerationExtensions
{
    extension(BbsSignature signature)
    {
        /// <summary>
        /// Produces a BBS+ proof of knowledge of <paramref name="signature"/>
        /// over <paramref name="header"/> and <paramref name="messages"/>,
        /// disclosing only the messages at <paramref name="disclosedIndices"/>,
        /// per IETF <c>draft-irtf-cfrg-bbs-signatures-10</c> Sections 3.5.1
        /// (ProofGen) and 3.6.3 (CoreProofGen).
        /// </summary>
        /// <param name="publicKey">The public key paired with the secret key the signature was produced under; required because <c>domain</c> binds the public key into the proof.</param>
        /// <param name="header">The header bytes the signer bound into the signature. The verifier must supply the same.</param>
        /// <param name="presentationHeader">Optional presentation-context bytes the Prover binds into this specific proof. May be empty.</param>
        /// <param name="messages">The full message vector. The signer signed this exact vector under <paramref name="header"/>.</param>
        /// <param name="disclosedIndices">Strictly ascending, deduplicated, all in <c>[0, messages.Length)</c>. The verifier learns only the messages at these positions.</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarSubtract">Backend scalar subtraction.</param>
        /// <param name="scalarMultiply">Backend scalar multiplication.</param>
        /// <param name="scalarNegate">Backend scalar negation.</param>
        /// <param name="scalarInvert">Backend scalar inverse.</param>
        /// <param name="randomScalars">Backend random-scalar source. Production callers pass an OS-RNG-backed implementation; tests pass the IETF mocked-RNG for byte-faithful reproduction.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (used during generator derivation).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the signature point <c>A</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for the signature point <c>A</c>.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>A proof wrapping a pool-rented byte buffer of size <c>272 + 32 * (messages.Length - disclosedIndices.Length)</c>.</returns>
        /// <exception cref="ArgumentException">When <paramref name="disclosedIndices"/> is not strictly ascending, contains a negative or out-of-range value, or has more entries than <paramref name="messages"/>; when <paramref name="publicKey"/>'s ciphersuite differs from <paramref name="signature"/>'s; or when the signature point <c>A</c> is off-curve, the identity, or outside the prime-order subgroup.</exception>
        /// <remarks>
        /// The signature is deserialized per the spec's <c>octets_to_signature</c>
        /// (Section 4.2.4.3): <c>A</c> must decode onto the curve, must not be the
        /// identity, and must lie in the prime-order subgroup. The subgroup check
        /// protects the Prover: an <c>A</c> outside the prime-order subgroup would
        /// carry a cofactor component that survives blinding into <c>Abar</c> and
        /// <c>Bbar</c>, giving a malicious Signer a covert channel that breaks
        /// proof unlinkability.
        /// </remarks>
        [SuppressMessage("Usage", "CA2208", Justification = "C# 14 extension blocks surface the receiver as a regular parameter; 'signature' is the receiver parameter whose point A fails validation.")]
        public BbsProof GenerateProof(
            BbsPublicKey publicKey,
            BbsHeader header,
            BbsPresentationHeader presentationHeader,
            ReadOnlyMemory<BbsMessage> messages,
            ReadOnlyMemory<int> disclosedIndices,
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

            if(signature.Ciphersuite != publicKey.Ciphersuite)
            {
                throw new ArgumentException("BBS+ signature and public key must share the same ciphersuite.", nameof(publicKey));
            }

            int totalMessages = messages.Length;
            ReadOnlySpan<int> disclosed = disclosedIndices.Span;
            int r = disclosed.Length;
            if(r > totalMessages)
            {
                throw new ArgumentException("disclosedIndices cannot exceed messages length.", nameof(disclosedIndices));
            }
            if(!BbsProofAlgorithm.AreIndicesValid(disclosed, totalMessages))
            {
                throw new ArgumentException("disclosedIndices must be strictly ascending, deduplicated, and in [0, messages.Length).", nameof(disclosedIndices));
            }

            int undisclosedCount = totalMessages - r;
            int[] undisclosed = BbsProofAlgorithm.ComputeUndisclosedIndices(disclosed, totalMessages);

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsGenerateProof, CurveParameterSet.Bls12Curve381);

            string apiId = signature.Ciphersuite.Identifier;

            //Decode signature into (A, e), then validate A per octets_to_signature
            //steps 5-7 (Section 4.2.4.3): on-curve, not the identity, in the
            //prime-order subgroup. See the remarks for why the Prover must check
            //this rather than trust the Signer.
            using G1Point a = G1Point.FromCanonical(signature.GetABytes(), CurveParameterSet.Bls12Curve381, pool);
            using Scalar e = Scalar.FromCanonical(signature.GetEBytes(), CurveParameterSet.Bls12Curve381, pool);

            if(!a.IsOnCurve(g1IsOnCurve) || a.IsIdentity || !a.IsInPrimeOrderSubgroup(g1IsInPrimeOrderSubgroup))
            {
                throw new ArgumentException("BBS+ signature point A must be a non-identity point in the prime-order subgroup.", nameof(signature));
            }

            ImmutableArray<Scalar> messageScalars = BbsAlgorithm.MessagesToScalars(messages, apiId, hashToScalar, pool);
            ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(totalMessages + 1, apiId, expandMessage, g1HashToCurve, pool);

            int randomScalarCount = 5 + undisclosedCount;
            Scalar[] randoms = new Scalar[randomScalarCount];

            try
            {
                //Sample 5 + U random scalars: r1, r2, e~, r1~, r3~, then m~_j for each undisclosed j.
                for(int i = 0; i < randomScalarCount; i++)
                {
                    randoms[i] = Scalar.FromRandom(randomScalars, CurveParameterSet.Bls12Curve381, pool);
                }

                //ProofInit (Section 3.7.1): (Abar, Bbar, D, T1, T2, domain).
                using BbsProofInitResult initResult = BbsProofAlgorithm.ProofInit(
                    publicKey,
                    a,
                    e,
                    generators.AsSpan(),
                    header.Bytes,
                    messageScalars.AsSpan(),
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

                //Collect disclosed message scalars for the challenge calc.
                Scalar[] disclosedScalars = new Scalar[r];
                for(int i = 0; i < r; i++)
                {
                    disclosedScalars[i] = messageScalars[disclosed[i]];
                }

                //ProofChallengeCalculate: c = hash_to_scalar(serialize(...) || I2OSP(len(ph), 8) || ph, api_id || "H2S_").
                using Scalar challenge = BbsProofAlgorithm.CalculateChallenge(
                    disclosed,
                    disclosedScalars,
                    initResult.ABar, initResult.BBar, initResult.D, initResult.T1, initResult.T2, initResult.Domain,
                    presentationHeader.Bytes,
                    apiId,
                    hashToScalar,
                    pool);

                //Collect undisclosed message scalars for ProofFinalize; the
                //references stay owned by messageScalars.
                Scalar[] undisclosedScalars = new Scalar[undisclosedCount];
                for(int i = 0; i < undisclosedCount; i++)
                {
                    undisclosedScalars[i] = messageScalars[undisclosed[i]];
                }

                //ProofFinalize (Section 3.7.2): responses + serialised proof bytes.
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
                try
                {
                    Tag proofTag = ProviderInstrumentation.StampTag(
                        BbsProof.GetAlgebraicTag(signature.Ciphersuite),
                        WellKnownBbsProviderIdentities.Library,
                        WellKnownBbsProviderIdentities.Crypto,
                        WellKnownBbsProviderIdentities.Class,
                        ProviderOperation.SignatureGenerateProof);
                    return new BbsProof(proofOwner, undisclosedCount, proofTag);
                }
                catch
                {
                    proofOwner.Dispose();
                    throw;
                }
            }
            finally
            {
                for(int i = 0; i < randoms.Length; i++)
                {
                    randoms[i]?.Dispose();
                }
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