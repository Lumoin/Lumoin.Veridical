using Lumoin.Veridical.Analysis.StatisticalTests;
using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// The result of one BaseFold leakage experiment: which experiment ran, at what
/// scale, the leakage verdict, the supporting statistical test (where the
/// experiment uses one), any observed-versus-baseline metric (the classifier's
/// accuracy versus chance), and a one-line human-readable summary.
/// </summary>
[DebuggerDisplay("{Experiment}: {Signal} ({Summary,nq})")]
public sealed class BaseFoldLeakageExperimentResult
{
    /// <summary>The experiment's name.</summary>
    public string Experiment { get; }

    /// <summary>The multilinear polynomial's variable count the experiment ran at.</summary>
    public int VariableCount { get; }

    /// <summary>The number of witnesses sampled.</summary>
    public int SampleCount { get; }

    /// <summary>The leakage verdict.</summary>
    public BaseFoldLeakageSignal Signal { get; }

    /// <summary>The supporting statistical test, for experiments that run one; <see langword="null"/> otherwise.</summary>
    public StatisticalTestResult? StatisticalTest { get; }

    /// <summary>The observed metric (the classifier's accuracy), where applicable; <see langword="null"/> otherwise.</summary>
    public double? ObservedMetric { get; }

    /// <summary>The baseline the observed metric is compared against (chance accuracy), where applicable; <see langword="null"/> otherwise.</summary>
    public double? BaselineMetric { get; }

    /// <summary>A one-line human-readable interpretation.</summary>
    public string Summary { get; }


    /// <summary>Builds an experiment result.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="experiment"/> or <paramref name="summary"/> is <see langword="null"/>.</exception>
    public BaseFoldLeakageExperimentResult(
        string experiment,
        int variableCount,
        int sampleCount,
        BaseFoldLeakageSignal signal,
        StatisticalTestResult? statisticalTest,
        double? observedMetric,
        double? baselineMetric,
        string summary)
    {
        ArgumentNullException.ThrowIfNull(experiment);
        ArgumentNullException.ThrowIfNull(summary);

        Experiment = experiment;
        VariableCount = variableCount;
        SampleCount = sampleCount;
        Signal = signal;
        StatisticalTest = statisticalTest;
        ObservedMetric = observedMetric;
        BaselineMetric = baselineMetric;
        Summary = summary;
    }
}
