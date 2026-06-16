using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Diagnostics.CodeAnalysis;

using static Lumoin.Veridical.Tests.Spartan.FoldChainTestFixtures;
using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Verifier-robustness leg of the <see cref="FoldChain"/> gate: a
/// tampered compressed proof is rejected, and a valid compressed proof
/// does not verify against a different final folded instance (binding to
/// the specific folded statement). Per-region tampering of the proof's
/// internal byte layout is already covered by
/// <see cref="MaskedSpartanFailureTests"/> — a compressed fold proof
/// shares the <see cref="MaskedSpartanProof"/> structure — so this leg
/// covers only the fold-specific cases.
/// </summary>
[TestClass]
internal sealed class FoldChainFailureTests
{
    private const int HyraxVectorLength = 2;


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations.")]
    public void TamperedCompressedProofRejected()
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), ScalarRandom);
        using MaskedSpartanProver prover = BuildMaskedProver(HyraxVectorLength, ScalarRandom);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(HyraxVectorLength, ScalarRandom);

        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();
        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), ScalarRandom);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness(), ScalarRandom);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof originalProof = Compress(chain, prover, proverTranscript, ScalarRandom);

        //Flip a byte in the witness-commitment region (offset 0) of the
        //compressed proof.
        byte[] tamperedBytes = originalProof.AsReadOnlySpan().ToArray();
        tamperedBytes[0] ^= 0xFF;
        using MaskedSpartanProof tamperedProof = RehydrateProof(tamperedBytes, originalProof);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = VerifyCompressed(verifier, tamperedProof, chain.Accumulator.Instance, verifierTranscript);

        Assert.IsFalse(verified, "A compressed fold proof with a flipped byte must be rejected.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations.")]
    public void WrongFinalInstanceRejected()
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), ScalarRandom);
        using MaskedSpartanProver prover = BuildMaskedProver(HyraxVectorLength, ScalarRandom);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(HyraxVectorLength, ScalarRandom);

        using RawR1csInstance template = BuildOneMultiplyInstance();

        //Chain A: one statement, its own random blinding → folded instance A.
        using FiatShamirTranscript foldTranscriptA = FreshTranscript();
        using FoldChain chainA = StartChain(template, provider, foldTranscriptA, ScalarRandom);
        StepRaw(chainA, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), ScalarRandom);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = Compress(chainA, prover, proverTranscript, ScalarRandom);

        //Chain B: a different statement and independent random blinding →
        //a distinct folded instance of the same dimensions. The provider is held
        //non-owningly by both chains, so reusing it across the two is fine.
        using FiatShamirTranscript foldTranscriptB = FreshTranscript();
        using FoldChain chainB = StartChain(template, provider, foldTranscriptB, ScalarRandom);
        StepRaw(chainB, BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness(), ScalarRandom);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = VerifyCompressed(verifier, proof, chainB.Accumulator.Instance, verifierTranscript);

        Assert.IsFalse(
            verified,
            "A compressed proof must not verify against a different final folded instance — it binds to the specific folded statement.");
    }
}