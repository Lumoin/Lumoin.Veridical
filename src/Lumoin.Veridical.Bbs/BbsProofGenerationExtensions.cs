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
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>A proof wrapping a pool-rented byte buffer of size <c>272 + 32 * (messages.Length - disclosedIndices.Length)</c>.</returns>
        /// <exception cref="ArgumentException">When <paramref name="disclosedIndices"/> is not strictly ascending, contains a negative or out-of-range value, or has more entries than <paramref name="messages"/>; or when <paramref name="publicKey"/>'s ciphersuite differs from <paramref name="signature"/>'s.</exception>
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

            //Decode signature into (A, e).
            using G1Point a = G1Point.FromCanonical(signature.GetABytes(), CurveParameterSet.Bls12Curve381, pool);
            using Scalar e = Scalar.FromCanonical(signature.GetEBytes(), CurveParameterSet.Bls12Curve381, pool);

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

                Scalar r1 = randoms[0];
                Scalar r2 = randoms[1];
                Scalar eTilde = randoms[2];
                Scalar r1Tilde = randoms[3];
                Scalar r3Tilde = randoms[4];
                ReadOnlySpan<Scalar> mTildes = randoms.AsSpan(5);

                G1Point q1 = generators[0];
                ReadOnlySpan<G1Point> hPoints = generators.AsSpan()[1..];

                //domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id).
                using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, hPoints, header.Bytes, apiId, hashToScalar, pool);

                //ProofInit step 2: B = P1 + Q_1 * domain + sum H_i * msg_i.
                using G1Point p1 = BbsP1Generator.GetForCiphersuite(signature.Ciphersuite, pool);
                using G1Point b = BbsAlgorithm.ComputeMessageCommitment(p1, q1, domain, hPoints, messageScalars.AsSpan(), g1Add, g1MultiScalarMultiply, pool);

                //ProofInit step 3: D = B * r2.
                using G1Point d = b.ScalarMultiply(r2, g1ScalarMultiply, pool);

                //ProofInit step 4: Abar = A * (r1 * r2).
                using Scalar r1TimesR2 = r1.Multiply(r2, scalarMultiply, pool);
                using G1Point aBar = a.ScalarMultiply(r1TimesR2, g1ScalarMultiply, pool);

                //ProofInit step 5: Bbar = D * r1 - Abar * e = MSM([D, Abar], [r1, -e]).
                using Scalar negE = e.Negate(scalarNegate, pool);
                G1Point[] bBarPoints = [d, aBar];
                Scalar[] bBarScalars = [r1, negE];
                using G1Point bBar = BbsProofAlgorithm.MultiScalarMultiply(bBarPoints, bBarScalars, g1MultiScalarMultiply, pool);

                //ProofInit step 6: T1 = Abar * e~ + D * r1~ = MSM([Abar, D], [e~, r1~]).
                G1Point[] t1Points = [aBar, d];
                Scalar[] t1Scalars = [eTilde, r1Tilde];
                using G1Point t1 = BbsProofAlgorithm.MultiScalarMultiply(t1Points, t1Scalars, g1MultiScalarMultiply, pool);

                //ProofInit step 7: T2 = D * r3~ + sum_{j in undisclosed} H_j * m~_j.
                G1Point[] t2Points = new G1Point[1 + undisclosedCount];
                Scalar[] t2Scalars = new Scalar[1 + undisclosedCount];
                t2Points[0] = d;
                t2Scalars[0] = r3Tilde;
                for(int i = 0; i < undisclosedCount; i++)
                {
                    t2Points[1 + i] = hPoints[undisclosed[i]];
                    t2Scalars[1 + i] = mTildes[i];
                }
                using G1Point t2 = BbsProofAlgorithm.MultiScalarMultiply(t2Points, t2Scalars, g1MultiScalarMultiply, pool);

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
                    aBar, bBar, d, t1, t2, domain,
                    presentationHeader.Bytes,
                    apiId,
                    hashToScalar,
                    pool);

                //ProofFinalize step 1: r3 = r2^-1.
                using Scalar r3 = r2.Invert(scalarInvert, pool);

                //ProofFinalize step 2: e^ = e~ + e * c.
                using Scalar eTimesC = e.Multiply(challenge, scalarMultiply, pool);
                using Scalar eHat = eTilde.Add(eTimesC, scalarAdd, pool);

                //ProofFinalize step 3: r1^ = r1~ - r1 * c.
                using Scalar r1TimesC = r1.Multiply(challenge, scalarMultiply, pool);
                using Scalar r1Hat = r1Tilde.Subtract(r1TimesC, scalarSubtract, pool);

                //ProofFinalize step 4: r3^ = r3~ - r3 * c.
                using Scalar r3TimesC = r3.Multiply(challenge, scalarMultiply, pool);
                using Scalar r3Hat = r3Tilde.Subtract(r3TimesC, scalarSubtract, pool);

                //ProofFinalize step 5: m^_j = m~_j + undisclosed_msg_j * c.
                Scalar[] mHats = new Scalar[undisclosedCount];
                try
                {
                    for(int i = 0; i < undisclosedCount; i++)
                    {
                        using Scalar msgTimesC = messageScalars[undisclosed[i]].Multiply(challenge, scalarMultiply, pool);
                        mHats[i] = mTildes[i].Add(msgTimesC, scalarAdd, pool);
                    }

                    //ProofFinalize step 6 + 7: serialise the proof as Abar || Bbar || D || e^ || r1^ || r3^ || m^_j... || c.
                    int proofSize = BbsProof.ComputeSizeBytes(undisclosedCount);
                    IMemoryOwner<byte> proofOwner = pool.Rent(proofSize);
                    try
                    {
                        Span<byte> dst = proofOwner.Memory.Span[..proofSize];
                        aBar.AsReadOnlySpan().CopyTo(dst[BbsProof.ABarOffset..]);
                        bBar.AsReadOnlySpan().CopyTo(dst[BbsProof.BBarOffset..]);
                        d.AsReadOnlySpan().CopyTo(dst[BbsProof.DOffset..]);
                        eHat.AsReadOnlySpan().CopyTo(dst.Slice(BbsProof.EHatOffset, Scalar.SizeBytes));
                        r1Hat.AsReadOnlySpan().CopyTo(dst.Slice(BbsProof.R1HatOffset, Scalar.SizeBytes));
                        r3Hat.AsReadOnlySpan().CopyTo(dst.Slice(BbsProof.R3HatOffset, Scalar.SizeBytes));
                        for(int i = 0; i < undisclosedCount; i++)
                        {
                            mHats[i].AsReadOnlySpan()
                                .CopyTo(dst.Slice(BbsProof.CommitmentsOffset + Scalar.SizeBytes * i, Scalar.SizeBytes));
                        }
                        challenge.AsReadOnlySpan()
                            .CopyTo(dst.Slice(BbsProof.CommitmentsOffset + Scalar.SizeBytes * undisclosedCount, Scalar.SizeBytes));

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
                    for(int i = 0; i < mHats.Length; i++)
                    {
                        mHats[i]?.Dispose();
                    }
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