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
/// Per-verifier-pseudonym commitment generation on
/// <see cref="BbsCommitmentWithProof"/>. CommitWithNym is the
/// prover-side capability: before pseudonym-bound blind issuance the
/// prover commits to any messages it wants signed without revealing them
/// together with its <c>prover_nyms</c> scalar vector — the prover's
/// share of the eventual <c>nym_secrets</c> — producing the
/// commitment-with-proof it sends to the signer plus the
/// <c>secret_prover_blind</c> scalar it keeps.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BbsNymCommitmentGenerationExtensions
{
    private static readonly ProviderOperation CommitWithNymOperation = new("BbsNymCommit");


    extension(BbsCommitmentWithProof)
    {
        /// <summary>
        /// Produces a Pedersen commitment over
        /// <paramref name="committedMessages"/> and
        /// <paramref name="proverNyms"/> together with a Schnorr proof of
        /// knowledge of its opening, per IETF
        /// <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c> Section
        /// 6.1.1 (CommitWithNym), composing the blind-BBS CoreCommit under
        /// the pseudonym Interface api_id.
        /// </summary>
        /// <param name="committedMessages">The prover-chosen messages to commit to; may be empty (the prover then commits only to its nym scalars and the blinding factor).</param>
        /// <param name="proverNyms">The prover's secret nym scalar vector; at least one entry. These occupy the LAST committed slots — position is load-bearing, because <c>BlindSignWithNym</c> folds the signer's entropy onto the last slot and the proof pipeline slices the nym secrets off the tail. The caller retains ownership and MUST keep them secret.</param>
        /// <param name="ciphersuite">The pseudonym Interface ciphersuite (<see cref="BbsCiphersuite.Bls12Curve381Sha256Pseudonym"/> or <see cref="BbsCiphersuite.Bls12Curve381Shake256Pseudonym"/>).</param>
        /// <param name="expandMessage">The RFC 9380 expand_message hash-to-field delegate for the ciphersuite's hash.</param>
        /// <param name="hashToScalar">Backend hash-to-scalar.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarMultiply">Backend scalar multiplication.</param>
        /// <param name="randomScalars">Backend random-scalar source. Production callers pass an OS-RNG-backed implementation; tests pass the IETF mocked-RNG (COMMIT DST) for byte-faithful reproduction. Exactly <c>M + N + 2</c> scalars are drawn in the draft-fixed order: <c>secret_prover_blind</c>, <c>s~</c>, then one <c>m~</c> per committed message and per nym scalar.</param>
        /// <param name="g1MultiScalarMultiply">Backend G1 multi-scalar multiplication.</param>
        /// <param name="g1HashToCurve">Backend G1 hash-to-curve (blind-generator derivation).</param>
        /// <param name="pool">The pool to rent destination buffers from.</param>
        /// <returns>
        /// The commitment-with-proof (<c>48 + 32 * (M + N + 2)</c> bytes,
        /// sent to the signer) and the <c>secret_prover_blind</c> scalar.
        /// The caller owns and disposes both values, and keeps the blinding
        /// factor private exactly as with the blind Interface's Commit.
        /// </returns>
        /// <exception cref="ArgumentNullException">When any delegate or <paramref name="pool"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When <paramref name="ciphersuite"/> is not a pseudonym Interface value or <paramref name="proverNyms"/> is empty.</exception>
        public static (BbsCommitmentWithProof CommitmentWithProof, Scalar SecretProverBlind) CommitWithNym(
            ReadOnlyMemory<BbsMessage> committedMessages,
            ReadOnlyMemory<Scalar> proverNyms,
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

            if(ciphersuite != BbsCiphersuite.Bls12Curve381Sha256Pseudonym && ciphersuite != BbsCiphersuite.Bls12Curve381Shake256Pseudonym)
            {
                throw new ArgumentException($"CommitWithNym is a pseudonym Interface operation; received ciphersuite '{ciphersuite.Identifier}'.", nameof(ciphersuite));
            }
            if(proverNyms.IsEmpty)
            {
                throw new ArgumentException("CommitWithNym requires at least one prover_nym scalar.", nameof(proverNyms));
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.BbsNymCommit, CurveParameterSet.Bls12Curve381);

            string apiId = ciphersuite.Identifier;
            int committedMessageCount = committedMessages.Length;
            int committedScalarCount = committedMessageCount + proverNyms.Length;

            ImmutableArray<Scalar> committedMessageScalars = BbsAlgorithm.MessagesToScalars(committedMessages, apiId, hashToScalar, pool);
            ImmutableArray<G1Point> blindGenerators = BbsAlgorithm.CreateGenerators(
                committedScalarCount + 1,
                BbsBlindAlgorithm.GetBlindGeneratorApiId(apiId),
                expandMessage,
                g1HashToCurve,
                pool);

            try
            {
                //CommitWithNym steps 1-2: the prover_nyms scalars enter the
                //committed vector directly (they are already scalars, never
                //message octets) and sit AFTER every committed message.
                Scalar[] combinedScalars = new Scalar[committedScalarCount];
                for(int i = 0; i < committedMessageCount; i++)
                {
                    combinedScalars[i] = committedMessageScalars[i];
                }
                for(int i = 0; i < proverNyms.Length; i++)
                {
                    combinedScalars[committedMessageCount + i] = proverNyms.Span[i];
                }

                (IMemoryOwner<byte> owner, Scalar secretProverBlind) = BbsBlindAlgorithm.CoreCommit(
                    combinedScalars,
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
                        CommitWithNymOperation);

                    return (new BbsCommitmentWithProof(owner, committedScalarCount, commitmentTag), secretProverBlind);
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
