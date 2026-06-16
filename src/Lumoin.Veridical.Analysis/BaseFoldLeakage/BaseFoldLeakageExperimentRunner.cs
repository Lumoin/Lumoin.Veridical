using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// Orchestrates the three BaseFold leakage experiments over a shared
/// <see cref="BaseFoldLeakageHarness"/> and returns one result per experiment.
/// The experiments probe, in increasing strength, whether the BaseFold proof
/// leaks witness information: a coarse byte-distribution test, a naive linear
/// classifier, and the structural commitment-recoverability demonstration.
/// </summary>
public static class BaseFoldLeakageExperimentRunner
{
    /// <summary>
    /// Runs all three experiments at the given scale and returns their results in
    /// order: byte-distribution, classifier, commitment-recoverability.
    /// </summary>
    /// <param name="harness">The wired BaseFold harness.</param>
    /// <param name="variableCount">The multilinear polynomial variable count.</param>
    /// <param name="sampleCount">The number of witnesses to sample per experiment.</param>
    /// <param name="significanceLevel">The significance level the statistical experiments take their verdict against.</param>
    /// <returns>The three experiment results.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="harness"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<BaseFoldLeakageExperimentResult> RunAll(
        BaseFoldLeakageHarness harness,
        int variableCount,
        int sampleCount,
        double significanceLevel = 0.05)
    {
        ArgumentNullException.ThrowIfNull(harness);

        return
        [
            BaseFoldByteStatisticsExperiment.Run(harness, variableCount, sampleCount, significanceLevel),
            BaseFoldClassifierExperiment.Run(harness, variableCount, sampleCount, significanceLevel),
            BaseFoldCommitmentRecoverabilityExperiment.Run(harness, variableCount, sampleCount)
        ];
    }
}
