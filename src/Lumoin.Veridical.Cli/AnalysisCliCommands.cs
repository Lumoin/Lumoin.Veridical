using Lumoin.Base;
using System;
using System.CommandLine;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The Analysis subcommands of the command line. Each forwards to <see cref="AnalysisOperations"/>, the same
/// operations the MCP tools call, and prints a plain-text report; the commands exit zero whenever the
/// experiment or test ran, because a finding is a result and not a failure.
/// </summary>
internal static class AnalysisCliCommands
{
    /// <summary>Builds <c>analysis-basefold-leakage</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildBaseFoldLeakageCommand()
    {
        Option<int> variables = new("--variables") { Description = "The number of committed-polynomial variables.", DefaultValueFactory = _ => AnalysisOperations.DefaultVariableCount };
        Option<int> samples = new("--samples") { Description = "The number of samples each experiment draws.", DefaultValueFactory = _ => AnalysisOperations.DefaultSampleCount };
        Option<double> significance = NewSignificanceOption();
        Option<bool> hiding = new("--hiding") { Description = "Run against the hiding (salted) commitment provider instead of the plain one." };

        Command command = new("analysis-basefold-leakage", "Run the BaseFold leakage experiments (byte statistics, classifier, commitment recoverability) and print one line per experiment.")
        {
            variables,
            samples,
            significance,
            hiding
        };

        command.SetAction(parseResult =>
        {
            try
            {
                Console.WriteLine(AnalysisOperations.BaseFoldLeakage(
                    parseResult.GetValue(variables),
                    parseResult.GetValue(samples),
                    parseResult.GetValue(significance),
                    parseResult.GetValue(hiding),
                    BaseMemoryPool.Shared));

                return 0;
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }
        });

        return command;
    }


    /// <summary>Builds <c>analysis-welch-t</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildWelchTCommand()
    {
        return BuildTwoSampleCommand("analysis-welch-t", "Run Welch's two-sample t-test over two files of numbers, one per line.", AnalysisOperations.WelchT);
    }


    /// <summary>Builds <c>analysis-ks</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildKolmogorovSmirnovCommand()
    {
        return BuildTwoSampleCommand("analysis-ks", "Run the two-sample Kolmogorov-Smirnov test over two files of numbers, one per line.", AnalysisOperations.KolmogorovSmirnov);
    }


    /// <summary>Builds <c>analysis-chi-squared</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildChiSquaredCommand()
    {
        Argument<string> observedArgument = new("observed-file") { Description = "Path to the observed counts, one integer per line, or - for standard input." };
        Argument<string> comparisonArgument = new("comparison-file") { Description = "Path to a second observed count set (homogeneity), or with --expected the expected counts (goodness of fit)." };
        Option<bool> expected = new("--expected") { Description = "Treat the comparison file as expected counts and test goodness of fit, instead of testing homogeneity of two observed sets." };
        Option<double> significance = NewSignificanceOption();

        Command command = new("analysis-chi-squared", "Run the chi-squared homogeneity test of two observed count sets, or with --expected the goodness-of-fit test.")
        {
            observedArgument,
            comparisonArgument,
            expected,
            significance
        };

        command.SetAction(parseResult =>
        {
            if(!Program.TryReadInput(parseResult.GetValue(observedArgument) ?? "-", "observed counts", out string observed)
                || !Program.TryReadInput(parseResult.GetValue(comparisonArgument) ?? string.Empty, "comparison counts", out string comparison))
            {
                return 1;
            }

            try
            {
                Console.WriteLine(AnalysisOperations.ChiSquared(observed, comparison, parseResult.GetValue(expected), parseResult.GetValue(significance)));

                return 0;
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }
        });

        return command;
    }


    private static Command BuildTwoSampleCommand(string name, string description, Func<string, string, double, string> operation)
    {
        Argument<string> firstArgument = new("first-file") { Description = "Path to the first sample set, one number per line, or - for standard input." };
        Argument<string> secondArgument = new("second-file") { Description = "Path to the second sample set, one number per line." };
        Option<double> significance = NewSignificanceOption();

        Command command = new(name, description)
        {
            firstArgument,
            secondArgument,
            significance
        };

        command.SetAction(parseResult =>
        {
            if(!Program.TryReadInput(parseResult.GetValue(firstArgument) ?? "-", "first sample set", out string first)
                || !Program.TryReadInput(parseResult.GetValue(secondArgument) ?? string.Empty, "second sample set", out string second))
            {
                return 1;
            }

            try
            {
                Console.WriteLine(operation(first, second, parseResult.GetValue(significance)));

                return 0;
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }
        });

        return command;
    }


    private static Option<double> NewSignificanceOption() => new("--significance") { Description = "The significance level, strictly between 0 and 1.", DefaultValueFactory = _ => AnalysisOperations.DefaultSignificanceLevel };
}
