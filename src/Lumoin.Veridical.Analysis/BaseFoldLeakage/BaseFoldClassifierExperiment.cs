using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// Experiment two: can a simple linear classifier predict a witness property from
/// the proof? Each witness is labelled by the low bit of its first evaluation;
/// proof bytes (normalised to <c>[0, 1]</c>) are the features. A logistic
/// regression trains on one split and is scored on a held-out split; test
/// accuracy materially above chance indicates the proof leaks the property.
/// </summary>
/// <remarks>
/// The classifier is deliberately naive (linear, on raw proof bytes). The
/// commitment is a hash of the witness, so the witness-to-proof relationship is
/// highly non-linear; a linear model on a high-dimensional proof with few samples
/// is expected to score near chance and overfit the training split. A near-chance
/// result is the honest expected outcome — it bounds what a simple attack
/// recovers, not what a structurally-aware one could (see the commitment
/// recoverability experiment).
/// </remarks>
public static class BaseFoldClassifierExperiment
{
    private const string Name = "classifier";
    private const int TrainingIterations = 200;
    private const double LearningRate = 0.1;
    private const double L2Regularisation = 0.01;
    private const double ChanceAccuracy = 0.5;


    /// <summary>Runs the classifier experiment at the given scale.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="harness"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static BaseFoldLeakageExperimentResult Run(BaseFoldLeakageHarness harness, int variableCount, int sampleCount, double significanceLevel = 0.05)
    {
        ArgumentNullException.ThrowIfNull(harness);
        ArgumentOutOfRangeException.ThrowIfLessThan(variableCount, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(sampleCount, 10);

        Scalar[] point = harness.SamplePoint(variableCount);
        try
        {
            double[][] features = new double[sampleCount][];
            int[] labels = new int[sampleCount];

            for(int i = 0; i < sampleCount; i++)
            {
                using MultilinearExtension polynomial = harness.SamplePolynomial(variableCount);
                labels[i] = polynomial.AsReadOnlySpan()[polynomial.FieldElementSizeBytes - 1] & 1;
                byte[] proof = harness.ProofBytes(polynomial, point);

                double[] feature = new double[proof.Length];
                for(int k = 0; k < proof.Length; k++)
                {
                    feature[k] = proof[k] / 255.0;
                }

                features[i] = feature;
            }

            //A 70/30 train/test split in sample order. The sampler is independent
            //of the label, so the split is unbiased.
            int trainCount = sampleCount * 7 / 10;
            int testCount = sampleCount - trainCount;
            if(trainCount < 2 || testCount < 2)
            {
                return new BaseFoldLeakageExperimentResult(
                    Name, variableCount, sampleCount, BaseFoldLeakageSignal.NotDetected,
                    StatisticalTestResult.Inconclusive(significanceLevel), observedMetric: null, baselineMetric: ChanceAccuracy,
                    "Too few samples to form train and test splits.");
            }

            double[][] trainFeatures = features[..trainCount];
            int[] trainLabels = labels[..trainCount];
            double[][] testFeatures = features[trainCount..];
            int[] testLabels = labels[trainCount..];

            double[] weights = LogisticRegressionClassifier.Train(trainFeatures, trainLabels, TrainingIterations, LearningRate, L2Regularisation);
            double accuracy = LogisticRegressionClassifier.Accuracy(weights, testFeatures, testLabels);

            //Is the accuracy beyond chance? Compare the (correct, incorrect) split
            //against the 50/50 a coin would give, via chi-squared goodness-of-fit.
            int correct = (int)Math.Round(accuracy * testCount);
            long[] observed = [correct, testCount - correct];
            double[] expected = [ChanceAccuracy * testCount, (1.0 - ChanceAccuracy) * testCount];
            StatisticalTestResult test = ChiSquaredTest.GoodnessOfFit(observed, expected, significanceLevel);

            BaseFoldLeakageSignal signal = test.Interpretation == StatisticalTestInterpretation.Reject && accuracy > ChanceAccuracy
                ? BaseFoldLeakageSignal.Detected
                : BaseFoldLeakageSignal.NotDetected;

            string summary = signal == BaseFoldLeakageSignal.Detected
                ? $"A linear classifier recovered the witness bit from proof bytes at {accuracy:P1} (chance {ChanceAccuracy:P0}, p = {test.PValue:G3}): the proof leaks the bit."
                : $"A linear classifier scored {accuracy:P1} on the witness bit (chance {ChanceAccuracy:P0}, p = {test.PValue:G3}); no leakage was recovered by this naive model.";

            return new BaseFoldLeakageExperimentResult(Name, variableCount, sampleCount, signal, test, accuracy, ChanceAccuracy, summary);
        }
        finally
        {
            DisposeAll(point);
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
