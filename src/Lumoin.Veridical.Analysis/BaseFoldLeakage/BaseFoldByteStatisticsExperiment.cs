using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// Experiment one: does the proof's byte-value distribution differ depending on a
/// structural property of the witness? Witnesses are split into two classes by a
/// one-bit property (the low bit of the first evaluation); the byte values of all
/// proofs in each class are aggregated into a 256-bin histogram and compared by a
/// chi-squared homogeneity statistic — whose significance is assessed against a
/// <em>label-permutation null</em>, not the analytic chi-squared distribution.
/// </summary>
/// <remarks>
/// <para>
/// The permutation null is load-bearing. Proof bytes are heavily dependent
/// <em>within</em> one proof: BaseFold base oracles are repetition words (the
/// same scalar serialized many times) and the per-query Merkle paths share
/// upper-tree digests, so the analytic chi-squared — which assumes independent
/// draws — rejects on pure structure for <em>any</em> labeling, including ones
/// independent of the witness (verified during batch SM: index-parity and
/// first-half-versus-last-half labelings rejected at p &lt; 1e-24). Comparing the
/// observed statistic against the same statistic under random relabelings of the
/// same proofs is valid under arbitrary intra-proof dependence: under the null
/// that proof bytes carry no witness-class information, the witness labeling is
/// exchangeable with any other.
/// </para>
/// <para>
/// This remains the bluntest of the probes: a failure to reject does not mean
/// there is no leakage, only that this aggregate statistic does not surface it.
/// </para>
/// </remarks>
public static class BaseFoldByteStatisticsExperiment
{
    private const string Name = "byte-distribution";
    private const int ByteValueCount = 256;

    //199 relabelings give the permutation p-value a resolution of 1/200 = 0.005,
    //comfortably below the default 0.05 significance level, at negligible cost
    //(each permutation only re-pools the precomputed per-proof histograms).
    private const int PermutationCount = 199;

    //A fixed xorshift seed: the permutation null needs reproducibility across
    //runs, not cryptographic randomness — the labels being permuted are public.
    private const ulong PermutationSeed = 0x5DEECE66DUL;


    /// <summary>Runs the byte-distribution experiment at the given scale.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="harness"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static BaseFoldLeakageExperimentResult Run(BaseFoldLeakageHarness harness, int variableCount, int sampleCount, double significanceLevel = 0.05)
    {
        ArgumentNullException.ThrowIfNull(harness);
        ArgumentOutOfRangeException.ThrowIfLessThan(variableCount, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(sampleCount, 2);

        Scalar[] point = harness.SamplePoint(variableCount);
        try
        {
            //Per-proof histograms; the pooled class histograms of any labeling
            //are sums of these, so the permutation null re-pools cheaply.
            var histograms = new long[sampleCount][];
            var labels = new int[sampleCount];
            int countOne = 0;

            for(int i = 0; i < sampleCount; i++)
            {
                using MultilinearExtension polynomial = harness.SamplePolynomial(variableCount);
                labels[i] = polynomial.AsReadOnlySpan()[polynomial.FieldElementSizeBytes - 1] & 1;
                countOne += labels[i];

                byte[] proof = harness.ProofBytes(polynomial, point);
                long[] histogram = new long[ByteValueCount];
                foreach(byte value in proof)
                {
                    histogram[value]++;
                }

                histograms[i] = histogram;
            }

            if(countOne == 0 || countOne == sampleCount)
            {
                return new BaseFoldLeakageExperimentResult(
                    Name, variableCount, sampleCount, BaseFoldLeakageSignal.NotDetected,
                    StatisticalTestResult.Inconclusive(significanceLevel), observedMetric: null, baselineMetric: null,
                    "Only one witness class was sampled; the two-class comparison could not run.");
            }

            double observed = PooledStatistic(histograms, labels, significanceLevel);

            //The permutation null: the same statistic under random relabelings
            //preserving the class sizes. p = (1 + #{permuted ≥ observed}) / (P + 1).
            ulong state = PermutationSeed;
            var permutedLabels = new int[sampleCount];
            labels.CopyTo(permutedLabels, 0);
            int atLeastAsExtreme = 0;
            for(int permutation = 0; permutation < PermutationCount; permutation++)
            {
                Shuffle(permutedLabels, ref state);
                if(PooledStatistic(histograms, permutedLabels, significanceLevel) >= observed)
                {
                    atLeastAsExtreme++;
                }
            }

            double permutationP = (1.0 + atLeastAsExtreme) / (PermutationCount + 1.0);
            StatisticalTestResult test = StatisticalTestResult.Decisive(observed, degreesOfFreedom: null, permutationP, significanceLevel);
            BaseFoldLeakageSignal signal = test.Interpretation == StatisticalTestInterpretation.Reject
                ? BaseFoldLeakageSignal.Detected
                : BaseFoldLeakageSignal.NotDetected;

            string summary = signal == BaseFoldLeakageSignal.Detected
                ? $"Proof byte-value distributions differ by witness class beyond the label-permutation null (permutation p = {test.PValue:G3}): the proof leaks the class label."
                : $"Proof byte-value distributions are within the label-permutation null (permutation p = {test.PValue:G3}); this coarse statistic surfaces no witness leakage.";

            return new BaseFoldLeakageExperimentResult(Name, variableCount, sampleCount, signal, test, observedMetric: null, baselineMetric: null, summary);
        }
        finally
        {
            DisposeAll(point);
        }
    }


    //The chi-squared homogeneity statistic of the two class-pooled histograms
    //under the given labeling. Only the statistic is used — its analytic p-value
    //is invalid under intra-proof byte dependence (see the type remarks).
    //
    //The 256-bin pooling adds run vector-width (VectorizedAccumulation, the
    //batch AC seam marker landed in batch PB); the byte-counting loop in Run
    //stays scalar -- histogram counting scatters, and a per-lane sub-histogram
    //split is not worth its complexity at these sample scales.
    private static double PooledStatistic(long[][] histograms, int[] labels, double significanceLevel)
    {
        long[] classZero = new long[ByteValueCount];
        long[] classOne = new long[ByteValueCount];
        for(int i = 0; i < histograms.Length; i++)
        {
            long[] target = labels[i] == 0 ? classZero : classOne;
            StatisticalTests.VectorizedAccumulation.AddInPlace(target, histograms[i]);
        }

        return ChiSquaredTest.Homogeneity(classZero, classOne, significanceLevel).TestStatistic;
    }


    //Fisher–Yates over the label vector with a xorshift64 step — deterministic,
    //reproducible, and statistically ample for a permutation null.
    private static void Shuffle(int[] labels, ref ulong state)
    {
        for(int i = labels.Length - 1; i >= 1; i--)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            int j = (int)(state % (ulong)(i + 1));
            (labels[i], labels[j]) = (labels[j], labels[i]);
        }
    }


    private static void DisposeAll(Scalar[] scalars)
    {
        foreach(Scalar scalar in scalars)
        {
            scalar.Dispose();
        }
    }
}
