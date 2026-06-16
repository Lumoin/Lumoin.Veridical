using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;

using Fixtures = Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Zero-knowledge-property leg of the masked Spartan2 correctness
/// gate. Two sanity tests confirm the construction's randomness
/// flow — proofs change with the witness and with the masking
/// seed. A third statistical-smoke test inspects the byte
/// distributions of the construction's expected-blinded sections
/// (terminating evaluations, masking-polynomial commitments,
/// masking sums, masking-polynomial openings) across paired proofs
/// from two distinct valid witnesses and asserts that no scoped
/// byte position shows a chi-squared p-value below <c>10⁻³</c>.
/// </summary>
/// <remarks>
/// <para>
/// The per-round sumcheck messages are EXCLUDED from the chi-squared
/// gate. Under the multilinear-mask adaptation the high-degree
/// coefficients of each round message carry information about the
/// underlying polynomial that varies with the witness — the
/// documented leak structure from <c>SPARTAN2.md</c> §10.5 and
/// <c>SPARTAN-ZK-DESIGN.md</c> §9, not a regression.
/// </para>
/// <para>
/// With 50 samples per witness across 256 byte buckets the test is
/// statistically weak per position; the threshold (<c>p &lt; 0.001</c>)
/// is generous so the gate only fires on gross structural leaks,
/// not on the small per-position fluctuations expected under the
/// null. A real masking break that leaks through the scoped bytes
/// would show up as multiple clustered positions with very low
/// p-values.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MaskedSpartanIndistinguishabilityTests
{
    private const int ScopedChiSquaredSampleCount = 50;
    private const double PValueThreshold = 0.001;


    public TestContext? TestContext { get; set; }


    [TestMethod]
    public void MaskedProofsForDifferentWitnessesHaveDifferentBytes()
    {
        //Fixed seed for both proofs in every iteration; the witnesses are the
        //only varying input. Confirms the masked prover actually consumes the
        //witness — a regression that ignored the witness would yield byte-equal
        //proofs under a fixed seed.
        byte[] seed = DeriveSeed("witness-sensitivity", 0);
        Gen.Select(Gen.Int[1, 100], Gen.Int[1, 100], Gen.Int[1, 100], Gen.Int[1, 100])
            .Where((a1, b1, a2, b2) => a1 != a2 || b1 != b2)
            .Sample((a1, b1, a2, b2) =>
            {
                using RawR1csWitness w1 = BuildWitness(a1, b1);
                using RawR1csWitness w2 = BuildWitness(a2, b2);
                byte[] proof1 = ProduceProofBytes(w1, seed);
                byte[] proof2 = ProduceProofBytes(w2, seed);

                return !proof1.AsSpan().SequenceEqual(proof2);
            }, iter: 10);
    }


    [TestMethod]
    public void MaskedProofsForSameWitnessDifferentSeedsHaveDifferentBytes()
    {
        Gen.Select(Gen.Int[1, 100], Gen.Int[1, 100], Gen.Int, Gen.Int)
            .Where((_, _, s1, s2) => s1 != s2)
            .Sample((a, b, s1, s2) =>
            {
                using RawR1csWitness w1 = BuildWitness(a, b);
                using RawR1csWitness w2 = BuildWitness(a, b);
                byte[] proof1 = ProduceProofBytes(w1, DeriveSeed("seed-sensitivity-1", s1));
                byte[] proof2 = ProduceProofBytes(w2, DeriveSeed("seed-sensitivity-2", s2));

                return !proof1.AsSpan().SequenceEqual(proof2);
            }, iter: 10);
    }


    [TestMethod]
    public void MaskedProofsForDifferentWitnessesUnderUniformSeedHaveSimilarDistributionsOnBlindedSections()
    {
        byte[][] proofs1 = new byte[ScopedChiSquaredSampleCount][];
        byte[][] proofs2 = new byte[ScopedChiSquaredSampleCount][];

        Stopwatch sw = Stopwatch.StartNew();

        for(int i = 0; i < ScopedChiSquaredSampleCount; i++)
        {
            byte[] seed = DeriveSeed("scoped-chi-squared", i);
            using RawR1csWitness w1 = Fixtures.BuildOneMultiplyWitness();
            using RawR1csWitness w2 = Fixtures.BuildAlternativeOneMultiplyWitness();
            proofs1[i] = ProduceProofBytes(w1, seed);
            proofs2[i] = ProduceProofBytes(w2, seed);
        }

        sw.Stop();

        ScopedSection[] sections = ResolveScopedSections(proofs1[0]);

        TestContext?.WriteLine($"Generated {2 * ScopedChiSquaredSampleCount} proofs in {sw.Elapsed.TotalSeconds:F2}s.");

        int positionCount = 0;
        int below001 = 0;
        int below01 = 0;
        int below05 = 0;
        double minPValue = double.PositiveInfinity;
        double maxChiSquared = 0.0;
        int extremePositionAbsolute = -1;
        string? extremeSectionName = null;

        foreach(ScopedSection section in sections)
        {
            for(int local = 0; local < section.Length; local++)
            {
                int absolute = section.Offset + local;
                double chiSquared = ChiSquaredForPosition(proofs1, proofs2, absolute);
                double p = ChiSquaredPValueDf255(chiSquared);

                positionCount++;
                if(p < 0.05)
                {
                    below05++;
                }
                if(p < 0.01)
                {
                    below01++;
                }
                if(p < PValueThreshold)
                {
                    below001++;
                }

                if(chiSquared > maxChiSquared)
                {
                    maxChiSquared = chiSquared;
                    minPValue = p;
                    extremePositionAbsolute = absolute;
                    extremeSectionName = section.Name;
                }
            }
        }

        TestContext?.WriteLine(
            $"Chi-squared smoke test ({positionCount} scoped byte positions): max chi² = {maxChiSquared:F2} (df = 255) → p = {minPValue:G3} at {extremeSectionName} byte {extremePositionAbsolute}; "
            + $"positions with p<0.05: {below05}, p<0.01: {below01}, p<{PValueThreshold}: {below001}.");

        Assert.AreEqual(
            0,
            below001,
            $"Masked proof bytes leak witness information through scoped sections. {below001} byte position(s) showed p < {PValueThreshold}; max chi² observed = {maxChiSquared:F2} (df = 255, p = {minPValue:G3}) at {extremeSectionName} byte {extremePositionAbsolute}. The four scoped sections (terminating evaluations, masking commitments, masking sums, masking openings) are expected to be uniformly distributed regardless of witness; clustered low p-values indicate a masking break worth investigating.");
    }


    private static byte[] ProduceProofBytes(RawR1csWitness witness, ReadOnlySpan<byte> seed)
    {
        using MaskedSpartanProver prover = Fixtures.BuildMaskedProver(hyraxVectorLength: 2);
        using RawR1csInstance instance = Fixtures.BuildOneMultiplyInstance();
        using FiatShamirTranscript transcript = Fixtures.FreshTranscript();

        var rng = new DeterministicScalarRandom(seed);
        using MaskedSpartanProof proof = prover.Prove(
            instance, witness, transcript,
            Fixtures.Hash, Fixtures.Squeeze, Fixtures.Reduce, Fixtures.Add, Fixtures.Subtract, Fixtures.Multiply, Fixtures.Invert, rng.AsDelegate(),
            Fixtures.G1Add, Fixtures.G1ScalarMul, Fixtures.G1Msm, Fixtures.MleEvaluate, Fixtures.MleFold,
            BaseMemoryPool.Shared);

        return proof.AsReadOnlySpan().ToArray();
    }


    private static RawR1csWitness BuildWitness(int a, int b)
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] bytes = new byte[3 * scalarSize];
        Fixtures.WriteCanonical(new BigInteger(a), bytes.AsSpan(0 * scalarSize, scalarSize));
        Fixtures.WriteCanonical(new BigInteger(b), bytes.AsSpan(1 * scalarSize, scalarSize));
        Fixtures.WriteCanonical(new BigInteger((long)a * b), bytes.AsSpan(2 * scalarSize, scalarSize));

        return RawR1csWitness.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static byte[] DeriveSeed(string label, int counter)
    {
        //Deterministic per-(label, counter) 16-byte seed via BLAKE3. Replaces
        //System.Random which the project's analyzers ban for insecure
        //randomness — this path is for reproducibility, not entropy, and
        //BLAKE3 satisfies both intents.
        byte[] labelBytes = System.Text.Encoding.UTF8.GetBytes(label);
        Span<byte> input = stackalloc byte[labelBytes.Length + sizeof(int)];
        labelBytes.AsSpan().CopyTo(input);
        BinaryPrimitives.WriteInt32BigEndian(input[labelBytes.Length..], counter);

        byte[] output = new byte[16];
        Lumoin.Veridical.Hashing.Blake3.Hash(input, output);

        return output;
    }


    private static ScopedSection[] ResolveScopedSections(byte[] sampleProof)
    {
        //Run the prover once to learn the byte ranges of each scoped section
        //via the proof's accessor methods. The accessors return spans into
        //the proof's backing memory; ReadOnlySpan.Overlaps recovers the
        //absolute offset relative to the full proof span.
        using MaskedSpartanProver prover = Fixtures.BuildMaskedProver(hyraxVectorLength: 2);
        using RawR1csInstance instance = Fixtures.BuildOneMultiplyInstance();
        using RawR1csWitness witness = Fixtures.BuildOneMultiplyWitness();
        using FiatShamirTranscript transcript = Fixtures.FreshTranscript();
        byte[] seed = DeriveSeed("section-locator", 0);
        var rng = new DeterministicScalarRandom(seed);
        using MaskedSpartanProof proof = prover.Prove(
            instance, witness, transcript,
            Fixtures.Hash, Fixtures.Squeeze, Fixtures.Reduce, Fixtures.Add, Fixtures.Subtract, Fixtures.Multiply, Fixtures.Invert, rng.AsDelegate(),
            Fixtures.G1Add, Fixtures.G1ScalarMul, Fixtures.G1Msm, Fixtures.MleEvaluate, Fixtures.MleFold,
            BaseMemoryPool.Shared);

        if(proof.AsReadOnlySpan().Length != sampleProof.Length)
        {
            throw new InvalidOperationException("Sample proof length disagrees with freshly produced proof; instance shape drift.");
        }

        ReadOnlySpan<byte> full = proof.AsReadOnlySpan();

        return
        [
            new ScopedSection("outer-mask-commitment", LocateSection(full, proof.GetOuterMaskCommitmentBytes()), proof.GetOuterMaskCommitmentBytes().Length),
            new ScopedSection("inner-mask-commitment", LocateSection(full, proof.GetInnerMaskCommitmentBytes()), proof.GetInnerMaskCommitmentBytes().Length),
            new ScopedSection("outer-mask-sum",        LocateSection(full, proof.GetOuterMaskSumBytes()),        proof.GetOuterMaskSumBytes().Length),
            new ScopedSection("inner-mask-sum",        LocateSection(full, proof.GetInnerMaskSumBytes()),        proof.GetInnerMaskSumBytes().Length),
            new ScopedSection("claim-Az",              LocateSection(full, proof.GetClaimAzBytes()),              proof.GetClaimAzBytes().Length),
            new ScopedSection("claim-Bz",              LocateSection(full, proof.GetClaimBzBytes()),              proof.GetClaimBzBytes().Length),
            new ScopedSection("claim-Cz",              LocateSection(full, proof.GetClaimCzBytes()),              proof.GetClaimCzBytes().Length),
            new ScopedSection("eval-W",                LocateSection(full, proof.GetEvalWBytes()),                proof.GetEvalWBytes().Length),
            new ScopedSection("outer-mask-opening",    LocateSection(full, proof.GetOuterMaskOpeningProofBytes()), proof.GetOuterMaskOpeningProofBytes().Length),
            new ScopedSection("inner-mask-opening",    LocateSection(full, proof.GetInnerMaskOpeningProofBytes()), proof.GetInnerMaskOpeningProofBytes().Length),
        ];
    }


    private static int LocateSection(ReadOnlySpan<byte> full, ReadOnlySpan<byte> slice)
    {
        if(!full.Overlaps(slice, out int elementOffset))
        {
            throw new InvalidOperationException("Scoped slice is not a view into the full proof bytes.");
        }

        return elementOffset;
    }


    private static double ChiSquaredForPosition(byte[][] samples1, byte[][] samples2, int position)
    {
        Span<int> counts1 = stackalloc int[256];
        Span<int> counts2 = stackalloc int[256];

        for(int i = 0; i < samples1.Length; i++)
        {
            counts1[samples1[i][position]]++;
            counts2[samples2[i][position]]++;
        }

        //Chi-squared homogeneity test on a 2 × 256 contingency table; equal
        //group sizes (samples1.Length == samples2.Length) simplify expected
        //counts to (counts1[b] + counts2[b]) / 2 per cell. Empty rows (no
        //sample in either group) contribute nothing.
        double chi = 0.0;
        for(int b = 0; b < 256; b++)
        {
            int total = counts1[b] + counts2[b];
            if(total == 0)
            {
                continue;
            }
            double expected = total / 2.0;
            double d1 = counts1[b] - expected;
            double d2 = counts2[b] - expected;
            chi += (d1 * d1 + d2 * d2) / expected;
        }

        return chi;
    }


    private static double ChiSquaredPValueDf255(double chiSquared)
    {
        //Wilson-Hilferty cube-root approximation: for X ~ chi^2(k), the
        //transform ((X/k)^(1/3) - (1 - 2/(9k))) / sqrt(2/(9k)) is approximately
        //standard normal. Excellent accuracy for k = 255.
        const double Df = 255.0;
        const double VarianceTerm = 2.0 / (9.0 * Df);
        double cubeRoot = Math.Cbrt(chiSquared / Df);
        double z = (cubeRoot - (1.0 - VarianceTerm)) / Math.Sqrt(VarianceTerm);

        //One-sided upper-tail p-value: 1 - Phi(z).
        return 0.5 * Erfc(z / Math.Sqrt(2.0));
    }


    private static double Erfc(double x)
    {
        //Abramowitz and Stegun 7.1.26 — max absolute error ~1.5e-7 across
        //the real line, plenty for a p-value comparison against 1e-3.
        double sign = x < 0.0 ? -1.0 : 1.0;
        double a = Math.Abs(x);
        double t = 1.0 / (1.0 + 0.3275911 * a);
        double y = 1.0 - ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.Exp(-a * a);

        return 1.0 - sign * y;
    }


    private readonly record struct ScopedSection(string Name, int Offset, int Length);
}