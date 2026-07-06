using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// A dudect-style leakage detector for constant-time claims. It runs an operation
/// many times under two input classes — a fixed secret and a random one — times
/// each run, and asks <see cref="WelchTTest"/> whether the two timing
/// distributions differ. A rejected null is evidence that the operation branches
/// on secret data; a fail-to-reject is the absence of detected leakage at the
/// measured scale, never a proof of constant time — the caveat on
/// <c>ConstantTimeComparison</c> holds here too: this measures, it does not
/// guarantee.
/// </summary>
/// <remarks>
/// Following dudect (Reparaz, Balasch, Verbauwhede 2016) the Welch test is run at
/// several crops of the slow tail, where OS scheduling — not the operation —
/// dominates, and the crop with the strongest evidence is reported. That
/// multiple-crop sweep is a detector, so read its p-value as a signal, not a
/// size-α guarantee: a rejection says "leakage detected", a fail-to-reject at every
/// crop says "none detected at this scale". Wall-clock timing on a shared runner is
/// noisy, so a caller on CI should report the result, not fail the build on it.
/// </remarks>
public static class TimingLeakageHarness
{
    /// <summary>
    /// Fills <paramref name="destination"/> with the input for measurement class
    /// <paramref name="classId"/> (0 = the fixed class, 1 = the random class),
    /// drawing any randomness it needs from <paramref name="entropy"/> (a fresh,
    /// deterministic pseudo-random buffer for each measurement).
    /// </summary>
    public delegate void ClassInputPreparer(int classId, ReadOnlySpan<byte> entropy, Span<byte> destination);

    /// <summary>Invokes the operation under measurement on one prepared input.</summary>
    public delegate void TimedOperation(ReadOnlySpan<byte> input);

    /// <summary>The default number of timed measurements split across the two classes.</summary>
    public const int DefaultMeasurementCount = 100000;

    /// <summary>The default number of untimed warm-up invocations run before measuring, to settle the JIT and caches.</summary>
    public const int DefaultWarmupCount = 10000;

    //A fixed xorshift64 seed so the class assignment and the random-class inputs
    //are reproducible across runs, like the permutation-test null.
    private const ulong DefaultSeed = 0x5DEECE66DUL;

    //Fractions of the combined sample kept before each Welch test: 1.0 is the
    //untrimmed test, the tighter crops discard the slow tail where scheduling noise
    //hides a difference the operation itself does not carry.
    private static readonly double[] KeptFractions = [1.0, 0.999, 0.99, 0.95, 0.9];


    /// <summary>
    /// Measures <paramref name="operation"/> under a fixed and a random input class
    /// and tests whether their timings differ.
    /// </summary>
    /// <param name="operation">The operation under measurement.</param>
    /// <param name="preparer">Builds the input for each class from a per-measurement entropy buffer.</param>
    /// <param name="inputLength">The length in bytes of the operation's input.</param>
    /// <param name="measurementCount">The number of timed runs to take.</param>
    /// <param name="warmupCount">The number of untimed warm-up runs to take first.</param>
    /// <param name="significanceLevel">The significance level the verdict is taken against.</param>
    /// <returns>The most extreme <see cref="WelchTTest"/> result across the crop sweep; see the type remarks for how to read it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="operation"/> or <paramref name="preparer"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a count or length is out of range.</exception>
    public static StatisticalTestResult Measure(
        TimedOperation operation,
        ClassInputPreparer preparer,
        int inputLength,
        int measurementCount = DefaultMeasurementCount,
        int warmupCount = DefaultWarmupCount,
        double significanceLevel = 0.05)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(preparer);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(inputLength);
        ArgumentOutOfRangeException.ThrowIfLessThan(measurementCount, 2);
        ArgumentOutOfRangeException.ThrowIfNegative(warmupCount);

        byte[] input = new byte[inputLength];
        byte[] entropy = new byte[inputLength];
        double[] fixedTimings = new double[measurementCount];
        double[] randomTimings = new double[measurementCount];
        int fixedCount = 0;
        int randomCount = 0;
        ulong state = DefaultSeed;

        for(int i = 0; i < warmupCount; i++)
        {
            FillEntropy(entropy, ref state);
            preparer(0, entropy, input);
            operation(input);
        }

        for(int i = 0; i < measurementCount; i++)
        {
            int classId = (int)(NextRandom(ref state) & 1UL);
            FillEntropy(entropy, ref state);
            preparer(classId, entropy, input);

            long start = Stopwatch.GetTimestamp();
            operation(input);
            long elapsed = Stopwatch.GetTimestamp() - start;

            if(classId == 0)
            {
                fixedTimings[fixedCount++] = elapsed;
            }
            else
            {
                randomTimings[randomCount++] = elapsed;
            }
        }

        return Detect(fixedTimings.AsSpan(0, fixedCount), randomTimings.AsSpan(0, randomCount), significanceLevel);
    }


    /// <summary>
    /// Runs the crop sweep and Welch test over two already-collected timing samples.
    /// Separated from <see cref="Measure"/> so the statistical decision is testable
    /// without taking live timings.
    /// </summary>
    /// <param name="fixedClassTimings">The timings observed under the fixed input class.</param>
    /// <param name="randomClassTimings">The timings observed under the random input class.</param>
    /// <param name="significanceLevel">The significance level the verdict is taken against.</param>
    /// <returns>
    /// The crop with the largest <c>|t|</c>; <see cref="StatisticalTestInterpretation.Inconclusive"/>
    /// when either class has fewer than two observations.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="significanceLevel"/> is outside <c>(0, 1)</c>.</exception>
    public static StatisticalTestResult Detect(
        ReadOnlySpan<double> fixedClassTimings,
        ReadOnlySpan<double> randomClassTimings,
        double significanceLevel = 0.05)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(significanceLevel, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(significanceLevel, 1.0);

        if(fixedClassTimings.Length < 2 || randomClassTimings.Length < 2)
        {
            return StatisticalTestResult.Inconclusive(significanceLevel);
        }

        //The crop cutoff is read from the combined distribution, so both classes are
        //trimmed at the same value and a class-dependent slow tail cannot itself bias
        //the comparison.
        int combined = fixedClassTimings.Length + randomClassTimings.Length;
        double[] pooledSorted = new double[combined];
        fixedClassTimings.CopyTo(pooledSorted);
        randomClassTimings.CopyTo(pooledSorted.AsSpan(fixedClassTimings.Length));
        Array.Sort(pooledSorted);

        double[] fixedCrop = new double[fixedClassTimings.Length];
        double[] randomCrop = new double[randomClassTimings.Length];

        StatisticalTestResult mostExtreme = StatisticalTestResult.Inconclusive(significanceLevel);
        double largestStatistic = -1.0;
        foreach(double keptFraction in KeptFractions)
        {
            int cutoffIndex = (int)(keptFraction * (combined - 1));
            double cutoff = pooledSorted[cutoffIndex];

            int fixedKept = CopyAtMost(fixedClassTimings, cutoff, fixedCrop);
            int randomKept = CopyAtMost(randomClassTimings, cutoff, randomCrop);

            StatisticalTestResult result = WelchTTest.TwoSample(
                fixedCrop.AsSpan(0, fixedKept),
                randomCrop.AsSpan(0, randomKept),
                significanceLevel);

            //The crop giving the strongest evidence of a difference wins the sweep.
            if(result.Interpretation != StatisticalTestInterpretation.Inconclusive
                && Math.Abs(result.TestStatistic) > largestStatistic)
            {
                largestStatistic = Math.Abs(result.TestStatistic);
                mostExtreme = result;
            }
        }

        return mostExtreme;
    }


    //Copies the entries of 'source' at or below 'cutoff' into 'destination',
    //returning how many were kept.
    private static int CopyAtMost(ReadOnlySpan<double> source, double cutoff, Span<double> destination)
    {
        int kept = 0;
        for(int i = 0; i < source.Length; i++)
        {
            if(source[i] <= cutoff)
            {
                destination[kept++] = source[i];
            }
        }

        return kept;
    }


    private static void FillEntropy(Span<byte> destination, ref ulong state)
    {
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)NextRandom(ref state);
        }
    }


    //xorshift64 — the same cheap, reproducible stream the permutation test draws.
    private static ulong NextRandom(ref ulong state)
    {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;

        return state;
    }
}
