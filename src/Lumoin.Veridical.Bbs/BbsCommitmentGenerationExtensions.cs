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
/// Blind BBS commitment generation on <see cref="BbsCommitmentWithProof"/>.
/// Commit is the prover-side capability: before blind issuance the
/// prover commits to its blinding factor and any messages it wants
/// signed without revealing them, producing the commitment-with-proof
/// it sends to the signer plus the <c>secret_prover_blind</c> scalar it
/// keeps.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsCommitmentGenerationExtensions
{
    private static readonly ProviderOperation CommitOperation = new("BbsCommit");


    extension(BbsCommitmentWithProof)
    {
        /// <summary>
        /// Produces a Pedersen commitment over <paramref name="committedMessages"/>
        /// together with a Schnorr proof of knowledge of its opening, per
        /// IETF <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Sections
        /// 4.1.1 (Commit) and 4.3.1 (CoreCommit).
        /// </summary>
        /// <param name="committedMessages">The prover-chosen messages to commit to; may be empty (the prover then commits only to the blinding factor).</param>
        /// <param name="ciphersuite">The Blind BBS Interface ciphersuite (<see cref="BbsCiphersuite.Bls12Curve381Sha256Blind"/> or <see cref="BbsCiphersuite.Bls12Curve381Shake256Blind"/>).</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate for the ciphersuite's hash.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarMultiply">Backend scalar multiplication.</param>
        /// <param name="randomScalars">Backend random-scalar source. Production callers pass an OS-RNG-backed implementation; tests pass the IETF mocked-RNG (COMMIT DST) for byte-faithful reproduction. Exactly <c>M + 2</c> scalars are drawn, in the draw order the draft fixes: <c>secret_prover_blind</c>, <c>s~</c>, then one <c>m~_i</c> per committed message.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (blind-generator derivation).</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>
        /// The commitment-with-proof (<c>48 + 32 * (M + 2)</c> bytes, sent to
        /// the signer) and the <c>secret_prover_blind</c> scalar. The blinding
        /// factor MUST stay private with the prover — it is needed again for
        /// <c>VerifyBlindSign</c> and for proof generation, and revealing it
        /// lets anyone unblind the commitment. The caller owns and disposes
        /// both values.
        /// </returns>
        /// <exception cref="ArgumentNullException">When any delegate or <paramref name="pool"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not a Blind BBS Interface value.</exception>
        public static (BbsCommitmentWithProof CommitmentWithProof, Scalar SecretProverBlind) Commit(
            ReadOnlyMemory<BbsMessage> committedMessages,
            BbsCiphersuite ciphersuite,
            ExpandMessageDelegate expandMessage,
            ScalarHashToScalarDelegate hashToScalar,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarRandomDelegate randomScalars,
            G1MultiScalarMultiplyDelegate g1MultiScalarMultiply,
            G1HashToCurveDelegate g1HashToCurve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(expandMessage);
            ArgumentNullException.ThrowIfNull(hashToScalar);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(randomScalars);
            ArgumentNullException.ThrowIfNull(g1MultiScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1HashToCurve);
            ArgumentNullException.ThrowIfNull(pool);

            if(ciphersuite != BbsCiphersuite.Bls12Curve381Sha256Blind && ciphersuite != BbsCiphersuite.Bls12Curve381Shake256Blind)
            {
                throw new ArgumentException($"Commit is a Blind BBS Interface operation; received ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsCommit, CurveParameterSet.Bls12Curve381);

            string apiId = ciphersuite.Identifier;
            int committedMessageCount = committedMessages.Length;

            ImmutableArray<Scalar> committedMessageScalars = BbsAlgorithm.MessagesToScalars(committedMessages, apiId, hashToScalar, pool);
            ImmutableArray<G1Point> blindGenerators = BbsAlgorithm.CreateGenerators(
                committedMessageCount + 1,
                BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                expandMessage,
                g1HashToCurve,
                pool);

            try
            {
                (IMemoryOwner<byte> owner, Scalar secretProverBlind) = BbsBlindAlgorithm.CoreCommit(
                    committedMessageScalars.AsSpan(),
                    blindGenerators.AsSpan(),
                    apiId,
                    hashToScalar,
                    scalarAdd,
                    scalarMultiply,
                    randomScalars,
                    g1MultiScalarMultiply,
                    pool);
                try
                {
                    Tag commitmentTag = ProviderInstrumentation.StampTag(
                        BbsCommitmentWithProof.GetAlgebraicTag(ciphersuite),
                        WellKnownBbsProviderIdentities.Library,
                        WellKnownBbsProviderIdentities.Crypto,
                        WellKnownBbsProviderIdentities.Class,
                        CommitOperation);

                    return (new BbsCommitmentWithProof(owner, committedMessageCount, commitmentTag), secretProverBlind);
                }
                catch
                {
                    owner.Dispose();
                    secretProverBlind.Dispose();
                    throw;
                }
            }
            finally
            {
                foreach(Scalar scalar in committedMessageScalars)
                {
                    scalar.Dispose();
                }
                foreach(G1Point generator in blindGenerators)
                {
                    generator.Dispose();
                }
            }
        }
    }
}
