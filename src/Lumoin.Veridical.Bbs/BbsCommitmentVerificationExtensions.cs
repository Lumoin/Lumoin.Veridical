using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// Blind BBS commitment verification on
/// <see cref="BbsCommitmentWithProof"/>. Verify is the signer-side
/// capability: before blind issuance the signer checks the prover's
/// Schnorr proof of knowledge of the commitment opening. BlindSign runs
/// this gate internally (<c>deserialize_and_validate_commit</c>); the
/// standalone surface lets a signer pre-validate a received commitment
/// without committing to an issuance.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsCommitmentVerificationExtensions
{
    extension(BbsCommitmentWithProof commitmentWithProof)
    {
        /// <summary>
        /// Verifies the Schnorr proof of knowledge of the commitment's
        /// opening per IETF <c>draft-irtf-cfrg-bbs-blind-signatures-03</c>
        /// Sections 4.1.2 (<c>deserialize_and_validate_commit</c>) and
        /// 4.3.2 (<c>CoreCommitVerify</c>). Returns <see langword="false"/>
        /// on any decode or validation failure; throws only on null
        /// arguments.
        /// </summary>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate for the ciphersuite's hash.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarNegate">Backend scalar negation.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (blind-generator derivation).</param>
        /// <param name="g1IsOnCurve">Backend G1 on-curve validation for the commitment point <c>C</c>.</param>
        /// <param name="g1IsInPrimeOrderSubgroup">Backend G1 prime-order-subgroup validation for <c>C</c>.</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns><see langword="true"/> when the commitment point validates and the proof of opening verifies; <see langword="false"/> otherwise.</returns>
        /// <remarks>
        /// The commitment point <c>C</c> must decode onto the curve, must
        /// not be the identity, and must lie in the prime-order subgroup
        /// before any algebra runs; the challenge comparison goes through
        /// <c>FixedTimeEquals</c>.
        /// </remarks>
        public bool Verify(
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarNegateDelegate scalarNegate,
            G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
            G1HashToCurveDelegate g1HashToCurve,
            G1IsOnCurveDelegate g1IsOnCurve,
            G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(commitmentWithProof);
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarNegate);
            ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1HashToCurve);
            ArgumentNullException.ThrowIfNull(g1IsOnCurve);
            ArgumentNullException.ThrowIfNull(g1IsInPrimeOrderSubgroup);
            ArgumentNullException.ThrowIfNull(pool);

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsCommitVerify, CurveParameterSet.Bls12Curve381);

            string apiId = commitmentWithProof.Ciphersuite.Identifier;

            ImmutableArray<G1Point> blindGenerators = BbsAlgorithm.CreateGenerators(
                commitmentWithProof.CommittedMessageCount + 1,
                BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                expandMessage,
                g1HashToCurve,
                pool);

            try
            {
                try
                {
                    G1Point? commitment = BbsBlindAlgorithm.DeserializeAndValidateCommit(
                        commitmentWithProof,
                        blindGenerators.AsSpan(),
                        apiId,
                        hashToScalar,
                        scalarNegate,
                        g1MultiScalarMultiply,
                        g1IsOnCurve,
                        g1IsInPrimeOrderSubgroup,
                        pool);
                    if(commitment is null)
                    {
                        return false;
                    }
                    commitment.Dispose();

                    return true;
                }
                catch(ArgumentException)
                {
                    //Decode failures: length/count mismatches surfaced by the
                    //canonical factories map to INVALID per the spec.
                    return false;
                }
                catch(InvalidOperationException)
                {
                    //Backend decode failures during MSM — the bytes decoded as
                    //length-valid but are not a valid algebraic object. Mirrors
                    //the core verify surfaces' two-clause contract.
                    return false;
                }
            }
            finally
            {
                foreach(G1Point generator in blindGenerators)
                {
                    generator.Dispose();
                }
            }
        }
    }
}
