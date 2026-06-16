using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// A two-sample test of witness-independence: at one fixed public point, proofs
/// are produced for two witness classes (split by the low bit of the first
/// evaluation) and each proof is projected to a real-valued metric (its mean byte
/// value). A Kolmogorov-Smirnov two-sample test asks whether the two classes'
/// metric distributions are the same. For a hiding (zero-knowledge) provider they
/// are — the proof distribution does not depend on the witness — so the test does
/// not reject (<see cref="BaseFoldLeakageSignal.NotDetected"/>); for a leaking
/// provider a class-dependent metric would let it reject.
/// </summary>
/// <remarks>
/// <para>
/// This is the empirically <em>measurable</em> form of the zero-knowledge claim
/// for this stack. A literal real-versus-simulated test would compare a real proof
/// against a simulator's output (design doc §5: sample salted roots as uniform
/// digests, masked round polynomials subject to the running claim, queried values
/// uniformly, then program the random oracle at the queried leaves). That
/// simulator needs a <em>programmable</em> Fiat-Shamir oracle; the production
/// transcript is a real BLAKE3 hash, so a faithful verifying simulator cannot be
/// built here. Comparing two real witness populations sidesteps that — both share
/// the field-modulus and layout structure, so the test isolates the one thing
/// zero-knowledge promises is absent: dependence on the witness.
/// </para>
/// <para>
/// The mean-byte projection is deliberately coarse (a single scalar per proof); a
/// failure to reject is the expected, honest outcome for both a hiding and — at
/// this projection — a non-hiding provider, since BaseFold proof bytes look
/// near-uniform regardless. The discriminating evidence is the structural
/// <see cref="BaseFoldCommitmentRecoverabilityExperiment"/>, which flips from
/// <see cref="BaseFoldLeakageSignal.StructurallyCertain"/> to
/// <see cref="BaseFoldLeakageSignal.NotDetected"/> under a hiding provider. This
/// experiment is the complementary witness-independence consistency check.
/// </para>
/// </remarks>
public static class BaseFoldProofWitnessIndependenceExperiment
{
    private const string Name = "witness-independence";
    private const int ByteScale = 255;


    /// <summary>Runs the witness-independence two-sample experiment at the given scale.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="harness"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static BaseFoldLeakageExperimentResult Run(BaseFoldLeakageHarness harness, int variableCount, int sampleCount, double significanceLevel = 0.05)
    {
        ArgumentNullException.ThrowIfNull(harness);
        ArgumentOutOfRangeException.ThrowIfLessThan(variableCount, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(sampleCount, 4);

        Scalar[] point = harness.SamplePoint(variableCount);
        try
        {
            double[] classZero = new double[sampleCount];
            double[] classOne = new double[sampleCount];
            int countZero = 0;
            int countOne = 0;

            for(int i = 0; i < sampleCount; i++)
            {
                using MultilinearExtension polynomial = harness.SamplePolynomial(variableCount);
                int label = polynomial.AsReadOnlySpan()[polynomial.FieldElementSizeBytes - 1] & 1;
                byte[] proof = harness.ProofBytes(polynomial, point);

                double metric = MeanByte(proof);
                if(label == 0)
                {
                    classZero[countZero++] = metric;
                }
                else
                {
                    classOne[countOne++] = metric;
                }
            }

            if(countZero < 2 || countOne < 2)
            {
                return new BaseFoldLeakageExperimentResult(
                    Name, variableCount, sampleCount, BaseFoldLeakageSignal.NotDetected,
                    StatisticalTestResult.Inconclusive(significanceLevel), observedMetric: null, baselineMetric: null,
                    "Fewer than two proofs in a witness class; the two-sample comparison could not run.");
            }

            StatisticalTestResult test = KolmogorovSmirnovTest.TwoSample(
                classZero.AsSpan(0, countZero), classOne.AsSpan(0, countOne), significanceLevel);

            BaseFoldLeakageSignal signal = test.Interpretation == StatisticalTestInterpretation.Reject
                ? BaseFoldLeakageSignal.Detected
                : BaseFoldLeakageSignal.NotDetected;

            string summary = signal == BaseFoldLeakageSignal.Detected
                ? $"Proof metric distributions differ by witness class (KS D = {test.TestStatistic:G3}, p = {test.PValue:G3}): the proof depends on the witness."
                : $"Proof metric distributions are statistically indistinguishable across witness classes (KS D = {test.TestStatistic:G3}, p = {test.PValue:G3}); the proof shows no witness dependence at this projection.";

            return new BaseFoldLeakageExperimentResult(Name, variableCount, sampleCount, signal, test, observedMetric: null, baselineMetric: null, summary);
        }
        finally
        {
            DisposeAll(point);
        }
    }


    //Projects a proof to a single real-valued metric: the mean of its byte values,
    //normalised to [0, 1]. Coarse by design (see the type remarks).
    private static double MeanByte(byte[] proof)
    {
        long total = 0;
        foreach(byte value in proof)
        {
            total += value;
        }

        return proof.Length == 0 ? 0.0 : (double)total / (proof.Length * ByteScale);
    }


    private static void DisposeAll(Scalar[] scalars)
    {
        foreach(Scalar scalar in scalars)
        {
            scalar.Dispose();
        }
    }
}
