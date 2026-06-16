using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// BBS+ selective-disclosure proof verification extension on
/// <see cref="BbsPublicKey"/>. VerifyProof is the Verifier-side
/// capability: a holder of the public key checks that a proof was
/// produced by someone holding a valid signature, with the
/// disclosed messages at the claimed positions.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsProofVerificationExtensions
{
    extension(BbsPublicKey publicKey)
    {
        /// <summary>
        /// Verifies a BBS+ proof against <paramref name="publicKey"/>,
        /// <paramref name="header"/>, <paramref name="presentationHeader"/>,
        /// and the supplied disclosed messages and indices, per IETF
        /// <c>draft-irtf-cfrg-bbs-signatures-10</c> Sections 3.5.2
        /// (ProofVerify) and 3.6.4 (CoreProofVerify). Returns
        /// <see langword="false"/> on any decode failure, ciphersuite
        /// mismatch, index inconsistency, or cryptographic failure;
        /// throws only on null arguments.
        /// </summary>
        /// <param name="proof">The proof to verify.</param>
        /// <param name="header">The header bytes that the Signer bound into the signature underlying the proof.</param>
        /// <param name="presentationHeader">The presentation-header bytes the Prover bound into this proof.</param>
        /// <param name="disclosedMessages">The disclosed messages, in original signing order. Parallel to <paramref name="disclosedIndices"/>.</param>
        /// <param name="disclosedIndices">Strictly ascending, deduplicated, all in <c>[0, totalMessages)</c> where <c>totalMessages = proof.UndisclosedMessageCount + disclosedIndices.Length</c>.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (generator derivation).</param>
        /// <param name="g2Add">Backend G2 addition.</param>
        /// <param name="g2ScalarMultiply">Backend G2 scalar multiplication.</param>
        /// <param name="pairing">Backend optimal-ate pairing.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns><see langword="true"/> when the proof is valid; <see langword="false"/> otherwise.</returns>
        /// <remarks>
        /// Uses the equivalent pairing form <c>e(Abar, W) == e(Bbar, BP2)</c>
        /// rather than the spec's <c>e(Abar, W) * e(Bbar, -BP2) == 1_GT</c>:
        /// the two are algebraically equal but the equivalent form avoids
        /// one Fp12 multiplication and one G2 negation.
        /// </remarks>
        public bool VerifyProof(
            BbsProof proof,
            BbsHeader header,
            BbsPresentationHeader presentationHeader,
            ReadOnlyMemory<BbsMessage> disclosedMessages,
            ReadOnlyMemory<int> disclosedIndices,
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
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1HashToCurve);
            ArgumentNullException.ThrowIfNull(g2Add);
            ArgumentNullException.ThrowIfNull(g2ScalarMultiply);
            ArgumentNullException.ThrowIfNull(pairing);
            ArgumentNullException.ThrowIfNull(pool);

            if(publicKey.Ciphersuite != proof.Ciphersuite)
            {
                return false;
            }

            ReadOnlySpan<int> disclosed = disclosedIndices.Span;
            int r = disclosed.Length;
            int u = proof.UndisclosedMessageCount;
            int totalMessages = r + u;

            if(disclosedMessages.Length != r)
            {
                return false;
            }
            if(!BbsProofAlgorithm.AreIndicesValid(disclosed, totalMessages))
            {
                return false;
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsVerifyProof, CurveParameterSet.Bls12Curve381);

            string apiId = publicKey.Ciphersuite.Identifier;

            //Decode the proof's G1 points and scalars inside try/catch — any malformed
            //slice (off-curve, out-of-subgroup, scalar >= field order) returns false.
            G1Point? aBar = null;
            G1Point? bBar = null;
            G1Point? d = null;
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

            ImmutableArray<Scalar> disclosedScalars = BbsAlgorithm.MessagesToScalars(disclosedMessages, apiId, hashToScalar, pool);
            ImmutableArray<G1Point> generators = BbsAlgorithm.CreateGenerators(totalMessages + 1, apiId, expandMessage, g1HashToCurve, pool);
            int[] undisclosed = BbsProofAlgorithm.ComputeUndisclosedIndices(disclosed, totalMessages);

            try
            {
                try
                {
                    G1Point q1 = generators[0];
                    ReadOnlySpan<G1Point> hPoints = generators.AsSpan()[1..];

                    using Scalar domain = BbsAlgorithm.CalculateDomain(publicKey, q1, hPoints, header.Bytes, apiId, hashToScalar, pool);

                    //ProofVerifyInit step 2: T1 = Bbar * c + Abar * e^ + D * r1^.
                    G1Point[] t1Points = [bBar!, aBar!, d!];
                    Scalar[] t1Scalars = [c!, eHat!, r1Hat!];
                    using G1Point t1 = BbsProofAlgorithm.MultiScalarMultiply(t1Points, t1Scalars, g1MultiScalarMultiply, pool);

                    //ProofVerifyInit step 3: Bv = P1 + Q_1 * domain + sum_{i in disclosed} H_i * msg_i.
                    using G1Point p1 = BbsP1Generator.GetForCiphersuite(publicKey.Ciphersuite, pool);
                    G1Point[] bvMsmPoints = new G1Point[1 + r];
                    Scalar[] bvMsmScalars = new Scalar[1 + r];
                    bvMsmPoints[0] = q1;
                    bvMsmScalars[0] = domain;
                    for(int i = 0; i < r; i++)
                    {
                        bvMsmPoints[1 + i] = hPoints[disclosed[i]];
                        bvMsmScalars[1 + i] = disclosedScalars[i];
                    }
                    using G1Point bvMsm = BbsProofAlgorithm.MultiScalarMultiply(bvMsmPoints, bvMsmScalars, g1MultiScalarMultiply, pool);
                    using G1Point bv = p1.Add(bvMsm, g1Add, pool);

                    //ProofVerifyInit step 4: T2 = Bv * c + D * r3^ + sum_{j in undisclosed} H_j * m^_j.
                    G1Point[] t2Points = new G1Point[2 + u];
                    Scalar[] t2Scalars = new Scalar[2 + u];
                    t2Points[0] = bv;
                    t2Scalars[0] = c!;
                    t2Points[1] = d!;
                    t2Scalars[1] = r3Hat!;
                    for(int i = 0; i < u; i++)
                    {
                        t2Points[2 + i] = hPoints[undisclosed[i]];
                        t2Scalars[2 + i] = mHats![i];
                    }
                    using G1Point t2 = BbsProofAlgorithm.MultiScalarMultiply(t2Points, t2Scalars, g1MultiScalarMultiply, pool);

                    //Re-derive the challenge and compare.
                    using Scalar challenge = BbsProofAlgorithm.CalculateChallenge(
                        disclosed,
                        disclosedScalars.AsSpan(),
                        aBar!, bBar!, d!, t1, t2, domain,
                        presentationHeader.Bytes,
                        apiId,
                        hashToScalar,
                        pool);

                    if(!challenge.AsReadOnlySpan().SequenceEqual(c!.AsReadOnlySpan()))
                    {
                        return false;
                    }

                    //Pairing check: e(Abar, W) == e(Bbar, BP2). Equivalent to the spec's e(Abar, W) * e(Bbar, -BP2) == 1_GT.
                    using G2Point w = G2Point.FromCanonical(publicKey.AsReadOnlySpan(), CurveParameterSet.Bls12Curve381, pool);
                    using G2Point bp2 = G2Point.Generator(CurveParameterSet.Bls12Curve381, pool);

                    using Fp12Element lhs = aBar!.PairWith(w, pairing, pool);
                    using Fp12Element rhs = bBar!.PairWith(bp2, pairing, pool);

                    return lhs.AsReadOnlySpan().SequenceEqual(rhs.AsReadOnlySpan());
                }
                catch(InvalidOperationException)
                {
                    //Backend decode failures during MSM/pairing — the bytes
                    //decoded as length-valid but are not a valid algebraic
                    //object (off-curve, wrong subgroup). Spec: octets_to_proof
                    //returns INVALID for such inputs; we mirror that by
                    //returning false rather than propagating.
                    return false;
                }
            }
            finally
            {
                //At this point all proof slices were decoded successfully (the catch
                //above returned false otherwise), so the locals are guaranteed
                //non-null. Disposing in declaration order.
                aBar.Dispose();
                bBar.Dispose();
                d.Dispose();
                eHat.Dispose();
                r1Hat.Dispose();
                r3Hat.Dispose();
                c.Dispose();
                for(int i = 0; i < mHats.Length; i++)
                {
                    mHats[i].Dispose();
                }
                foreach(Scalar scalar in disclosedScalars)
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