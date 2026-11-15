using Lumoin.Base;
using Lumoin.Veridical.Analysis.BaseFoldLeakage;
using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Hashing;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The Analysis operations behind the <c>analysis-*</c> subcommands and their MCP tools: the BaseFold leakage
/// experiments and the statistical tests the investigations are built from, each returned as a plain-text
/// report. Sample files hold one number per line.
/// </summary>
internal static class AnalysisOperations
{
    /// <summary>The default number of committed-polynomial variables of the leakage experiments.</summary>
    public const int DefaultVariableCount = 3;

    /// <summary>The default number of samples the leakage experiments draw.</summary>
    public const int DefaultSampleCount = 200;

    /// <summary>The default significance level of the statistical tests.</summary>
    public const double DefaultSignificanceLevel = 0.05;

    //The number of BaseFold query repetitions the leakage experiments use.
    private const int QueryCount = 8;

    private const string CodeSeedText = "veridical.analysis.basefold-leakage.code.v1";

    private const string RoundTripFormat = "R";


    /// <summary>Runs the BaseFold leakage experiments against the plain or the hiding commitment provider.</summary>
    /// <param name="variableCount">The number of committed-polynomial variables.</param>
    /// <param name="sampleCount">The number of samples each experiment draws.</param>
    /// <param name="significanceLevel">The significance level of the statistical experiments.</param>
    /// <param name="hiding">Whether to run against the hiding (salted) provider instead of the plain one.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The report, one line per experiment.</returns>
    /// <exception cref="ArgumentException">An argument is out of range.</exception>
    public static string BaseFoldLeakage(int variableCount, int sampleCount, double significanceLevel, bool hiding, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(variableCount < 1)
        {
            throw new ArgumentException("The variable count is at least 1.", nameof(variableCount));
        }

        if(sampleCount < 2)
        {
            throw new ArgumentException("The sample count is at least 2.", nameof(sampleCount));
        }

        ValidateSignificance(significanceLevel);

        CurveParameterSet curve = CurveParameterSet.Bls12Curve381;
        using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
        FiatShamirHashDelegate hash = Blake3FiatShamirBackend.GetHash();
        FiatShamirSqueezeDelegate squeeze = Blake3FiatShamirBackend.GetSqueeze();
        ScalarHashToScalarDelegate hashToScalar = Bls12Curve381ManagedScalarBackend.GetHashToScalarSha256();
        byte[] codeSeed = Encoding.UTF8.GetBytes(CodeSeedText);
        int digestSize = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

        using PolynomialCommitmentProvider provider = hiding
            ? ZkBaseFoldPolynomialCommitmentScheme.Create(
                codeSeed, curve, QueryCount, HashTwoToOne, hash, squeeze, scalar.Reduce, scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, scalar.Random, hashToScalar, pool, digestSize)
            : BaseFoldPolynomialCommitmentScheme.Create(
                codeSeed, curve, QueryCount, HashTwoToOne, hash, squeeze, scalar.Reduce, scalar.Add, scalar.Subtract, scalar.Multiply, scalar.Invert, hashToScalar, pool, digestSize);
        var harness = new BaseFoldLeakageHarness(
            provider,
            curve,
            scalar.Random,
            () => FiatShamirTranscript.Initialise(
                new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
                ReadOnlySpan<byte>.Empty,
                WellKnownHashAlgorithms.Blake3,
                hash,
                pool),
            pool);

        IReadOnlyList<BaseFoldLeakageExperimentResult> results = BaseFoldLeakageExperimentRunner.RunAll(harness, variableCount, sampleCount, significanceLevel);
        var report = new StringBuilder();
        report.Append(CultureInfo.InvariantCulture, $"BaseFold leakage experiments ({(hiding ? "hiding" : "plain")} provider, {variableCount} variable(s), {sampleCount} sample(s))");
        foreach(BaseFoldLeakageExperimentResult result in results)
        {
            report.AppendLine().Append(CultureInfo.InvariantCulture, $"[{result.Experiment}] signal={result.Signal} | {result.Summary}");
        }

        return report.ToString();
    }


    /// <summary>Runs Welch's two-sample t-test over two sample sets.</summary>
    /// <param name="first">The first sample set, one number per line.</param>
    /// <param name="second">The second sample set, one number per line.</param>
    /// <param name="significanceLevel">The significance level.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentException">An input is not a list of numbers or the level is out of range.</exception>
    public static string WelchT(string first, string second, double significanceLevel)
    {
        ValidateSignificance(significanceLevel);

        return Describe("Welch two-sample t-test", WelchTTest.TwoSample(ParseNumbers(first, "first sample set"), ParseNumbers(second, "second sample set"), significanceLevel));
    }


    /// <summary>Runs the two-sample Kolmogorov-Smirnov test over two sample sets.</summary>
    /// <param name="first">The first sample set, one number per line.</param>
    /// <param name="second">The second sample set, one number per line.</param>
    /// <param name="significanceLevel">The significance level.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentException">An input is not a list of numbers or the level is out of range.</exception>
    public static string KolmogorovSmirnov(string first, string second, double significanceLevel)
    {
        ValidateSignificance(significanceLevel);

        return Describe("two-sample Kolmogorov-Smirnov test", KolmogorovSmirnovTest.TwoSample(ParseNumbers(first, "first sample set"), ParseNumbers(second, "second sample set"), significanceLevel));
    }


    /// <summary>
    /// Runs the chi-squared goodness-of-fit test of observed counts against expected counts, or the
    /// homogeneity test of two observed count sets.
    /// </summary>
    /// <param name="observed">The observed counts, one integer per line.</param>
    /// <param name="comparison">The expected counts (one number per line) for goodness of fit, or a second observed set (one integer per line) for homogeneity.</param>
    /// <param name="goodnessOfFit">Whether <paramref name="comparison"/> holds expected counts.</param>
    /// <param name="significanceLevel">The significance level.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentException">An input is not a list of numbers or the level is out of range.</exception>
    public static string ChiSquared(string observed, string comparison, bool goodnessOfFit, double significanceLevel)
    {
        ValidateSignificance(significanceLevel);
        long[] observedCounts = ParseCounts(observed, "observed counts");

        return goodnessOfFit
            ? Describe("chi-squared goodness-of-fit test", ChiSquaredTest.GoodnessOfFit(observedCounts, ParseNumbers(comparison, "expected counts"), significanceLevel))
            : Describe("chi-squared homogeneity test", ChiSquaredTest.Homogeneity(observedCounts, ParseCounts(comparison, "second observed counts"), significanceLevel));
    }


    private static string Describe(string name, StatisticalTestResult result)
    {
        var report = new StringBuilder();
        report.Append(CultureInfo.InvariantCulture, $"{name}: {result.Interpretation}");
        if(result.Interpretation != StatisticalTestInterpretation.Inconclusive)
        {
            report.Append(CultureInfo.InvariantCulture, $" | statistic={result.TestStatistic.ToString(RoundTripFormat, CultureInfo.InvariantCulture)}");
            if(result.DegreesOfFreedom is int degrees)
            {
                report.Append(CultureInfo.InvariantCulture, $" | degrees of freedom={degrees}");
            }

            report.Append(CultureInfo.InvariantCulture, $" | p={result.PValue.ToString(RoundTripFormat, CultureInfo.InvariantCulture)} | significance={result.SignificanceLevel.ToString(RoundTripFormat, CultureInfo.InvariantCulture)}");
        }

        return report.ToString();
    }


    private static void ValidateSignificance(double significanceLevel)
    {
        if(!(significanceLevel > 0.0 && significanceLevel < 1.0))
        {
            throw new ArgumentException("The significance level is strictly between 0 and 1.", nameof(significanceLevel));
        }
    }


    private static double[] ParseNumbers(string text, string what)
    {
        ArgumentNullException.ThrowIfNull(text);

        string[] lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var numbers = new double[lines.Length];
        for(int i = 0; i < lines.Length; i++)
        {
            if(!double.TryParse(lines[i], NumberStyles.Float, CultureInfo.InvariantCulture, out numbers[i]) || !double.IsFinite(numbers[i]))
            {
                throw new ArgumentException($"The {what} holds one finite number per line; line {(i + 1).ToString(CultureInfo.InvariantCulture)} is '{lines[i]}'.", nameof(text));
            }
        }

        return numbers;
    }


    private static long[] ParseCounts(string text, string what)
    {
        ArgumentNullException.ThrowIfNull(text);

        string[] lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var counts = new long[lines.Length];
        for(int i = 0; i < lines.Length; i++)
        {
            if(!long.TryParse(lines[i], NumberStyles.None, CultureInfo.InvariantCulture, out counts[i]))
            {
                throw new ArgumentException($"The {what} holds one non-negative integer per line; line {(i + 1).ToString(CultureInfo.InvariantCulture)} is '{lines[i]}'.", nameof(text));
            }
        }

        return counts;
    }


    //The two-to-one Merkle compression BLAKE3(left || right).
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        Blake3.Hash(combined, output);
    }
}
