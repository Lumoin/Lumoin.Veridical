using System;
using System.Globalization;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// Chooses the seed of a seeded sweep. A sweep keeps its own fixed seed so a local run is
/// reproducible; when the <see cref="VariableName"/> environment variable holds a 64-bit
/// unsigned decimal value, that value is mixed into the fixed seed so each run of a
/// continuous-integration pipeline samples new inputs while every sweep keeps a stream
/// distinct from the others.
/// </summary>
internal static class TestSeed
{
    /// <summary>The name of the environment variable that varies the seeds of the sweeps.</summary>
    public const string VariableName = "VERIDICAL_TEST_SEED";


    /// <summary>
    /// Returns the seed a sweep must use: <paramref name="fixedSeed"/> when the environment
    /// variable is unset or does not hold a 64-bit unsigned decimal value, otherwise the first
    /// output of a SplitMix64 stream started at the sum of <paramref name="fixedSeed"/> and the
    /// variable's value.
    /// </summary>
    /// <param name="fixedSeed">The sweep's own fixed seed.</param>
    /// <returns>The effective seed.</returns>
    public static ulong Resolve(ulong fixedSeed)
    {
        if(!TryReadVariable(out ulong value))
        {
            return fixedSeed;
        }

        SeededByteStream mixer = new(unchecked(fixedSeed + value));

        return mixer.NextUInt64();
    }


    /// <summary>
    /// Describes <paramref name="effectiveSeed"/> for a failure message, including the exact
    /// environment setting that regenerates the same inputs.
    /// </summary>
    /// <param name="effectiveSeed">The seed returned by <see cref="Resolve"/>.</param>
    /// <returns>The seed and how to reproduce it.</returns>
    public static string Describe(ulong effectiveSeed)
    {
        if(TryReadVariable(out ulong value))
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"seed 0x{effectiveSeed:X16}, reproduce with {VariableName}={value}");
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"seed 0x{effectiveSeed:X16}, the fixed seed used when {VariableName} is unset");
    }


    /// <summary>Reads the environment variable as a 64-bit unsigned decimal value.</summary>
    private static bool TryReadVariable(out ulong value)
    {
        string? text = Environment.GetEnvironmentVariable(VariableName);

        return ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }
}
