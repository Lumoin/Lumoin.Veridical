using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Spartan;
using System;

using static Lumoin.Veridical.Tests.Spartan.FoldChainTestFixtures;
using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Zero-knowledge-property leg of the <see cref="FoldChain"/> gate. Two
/// sanity tests confirm the randomness flow — the compressed proof
/// changes with the folded statement and with the blinding seed. A third
/// statistical-smoke test inspects the expected-blinded sections of
/// compressed proofs produced by folding two different statements into a
/// blinding instance under a shared per-sample seed, and asserts no
/// scoped byte position shows a chi-squared p-value below <c>10⁻³</c> —
/// the blinding accumulator hides which statement was folded. The
/// underlying masked prover's witness-indistinguishability is gated
/// separately by <see cref="MaskedSpartanIndistinguishabilityTests"/>;
/// this leg checks the end-to-end fold-then-compress composition.
/// </summary>
[TestClass]
internal sealed class FoldChainIndistinguishabilityTests
{
    private const int HyraxVectorLength = 2;
    private const int ScopedChiSquaredSampleCount = 40;
    private const double PValueThreshold = 0.001;


    public TestContext? TestContext { get; set; }


    private delegate RawR1csWitness RawWitnessFactory();


    [TestMethod]
    public void CompressedProofsForDifferentStatementsDiffer()
    {
        //Same blinding seed; the folded statement is the only varying
        //input. A chain that ignored the statement would yield byte-equal
        //compressed proofs.
        byte[] seed = ScopedProofIndistinguishability.DeriveSeed("fold-statement-sensitivity", 0);
        byte[] proof1 = ProduceCompressedProofBytes(BuildOneMultiplyWitness, seed);
        byte[] proof2 = ProduceCompressedProofBytes(BuildAlternativeOneMultiplyWitness, seed);

        Assert.IsFalse(
            proof1.AsSpan().SequenceEqual(proof2),
            "Compressed proofs for different folded statements under the same blinding seed must differ.");
    }


    [TestMethod]
    public void CompressedProofsForDifferentBlindingSeedsDiffer()
    {
        //Same statement; the blinding seed is the only varying input.
        byte[] proof1 = ProduceCompressedProofBytes(BuildOneMultiplyWitness, ScopedProofIndistinguishability.DeriveSeed("fold-seed-sensitivity", 1));
        byte[] proof2 = ProduceCompressedProofBytes(BuildOneMultiplyWitness, ScopedProofIndistinguishability.DeriveSeed("fold-seed-sensitivity", 2));

        Assert.IsFalse(
            proof1.AsSpan().SequenceEqual(proof2),
            "Compressed proofs for the same statement under different blinding seeds must differ.");
    }


    [TestMethod]
    public void CompressedProofBlindedSectionsAreIndistinguishableAcrossStatements()
    {
        byte[][] proofs1 = new byte[ScopedChiSquaredSampleCount][];
        byte[][] proofs2 = new byte[ScopedChiSquaredSampleCount][];

        for(int i = 0; i < ScopedChiSquaredSampleCount; i++)
        {
            //Per-sample shared seed: the blinding instance and the masking
            //are identical between the two proofs of a sample, so the only
            //difference is which statement was folded in.
            byte[] seed = ScopedProofIndistinguishability.DeriveSeed("fold-scoped-chi-squared", i);
            proofs1[i] = ProduceCompressedProofBytes(BuildOneMultiplyWitness, seed);
            proofs2[i] = ProduceCompressedProofBytes(BuildAlternativeOneMultiplyWitness, seed);
        }

        ScopedProofIndistinguishability.ScopedSection[] sections = ResolveSections();
        ScopedProofIndistinguishability.HomogeneityResult result =
            ScopedProofIndistinguishability.RunHomogeneity(proofs1, proofs2, sections, PValueThreshold);

        TestContext?.WriteLine(
            $"Fold chi-squared smoke test ({result.PositionCount} scoped byte positions): max chi² = {result.MaxChiSquared:F2} (df = 255) → p = {result.MinPValue:G3} at {result.ExtremeSection} byte {result.ExtremePosition}; "
            + $"positions with p<0.05: {result.Below05}, p<0.01: {result.Below01}, p<{PValueThreshold}: {result.BelowThreshold}.");

        Assert.AreEqual(
            0,
            result.BelowThreshold,
            $"Compressed fold proof leaks which statement was folded through scoped sections. {result.BelowThreshold} byte position(s) showed p < {PValueThreshold}; max chi² = {result.MaxChiSquared:F2} (df = 255, p = {result.MinPValue:G3}) at {result.ExtremeSection} byte {result.ExtremePosition}. The blinding accumulator is expected to make the scoped sections uniform regardless of the folded statement; clustered low p-values indicate a blinding/masking break worth investigating.");
    }


    private static byte[] ProduceCompressedProofBytes(RawWitnessFactory witnessFactory, byte[] seed)
    {
        var rng = new DeterministicScalarRandom(seed);
        ScalarRandomDelegate random = rng.AsDelegate();

        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), random);
        using MaskedSpartanProver prover = BuildMaskedProver(HyraxVectorLength, random);

        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, random);
        StepRaw(chain, BuildOneMultiplyInstance(), witnessFactory(), random);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = Compress(chain, prover, proverTranscript, random);

        return proof.AsReadOnlySpan().ToArray();
    }


    private static ScopedProofIndistinguishability.ScopedSection[] ResolveSections()
    {
        //One representative compressed proof to learn the scoped byte
        //ranges; offsets are stable across statements for a fixed shape.
        var rng = new DeterministicScalarRandom(ScopedProofIndistinguishability.DeriveSeed("fold-section-locator", 0));
        ScalarRandomDelegate random = rng.AsDelegate();

        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), random);
        using MaskedSpartanProver prover = BuildMaskedProver(HyraxVectorLength, random);
        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, random);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), random);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = Compress(chain, prover, proverTranscript, random);

        return ScopedProofIndistinguishability.ResolveScopedSections(proof);
    }
}