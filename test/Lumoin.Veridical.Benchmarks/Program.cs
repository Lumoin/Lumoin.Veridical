using BenchmarkDotNet.Running;
using System;
using System.Diagnostics;
using System.Globalization;

namespace Lumoin.Veridical.Benchmarks;

internal static class Program
{
    /// <summary>
    /// Runs benchmarks via BenchmarkDotNet's
    /// <see cref="BenchmarkSwitcher"/>, which discovers every
    /// public type with at least one <c>[Benchmark]</c> method in
    /// the executing assembly. The <c>--blake3-hotloop &lt;iterations&gt;</c>
    /// argument switches to a tight Blake3.Hash loop suitable for
    /// attaching <c>dotnet-trace</c> to identify SIMD hot spots.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Common invocations: <c>dotnet run -c Release</c> launches
    /// an interactive selector; <c>dotnet run -c Release -- --filter "*"</c>
    /// runs everything; <c>dotnet run -c Release -- --filter "*MsmBenchmark*"</c>
    /// runs one benchmark class.
    /// </para>
    /// <para>
    /// Profile capture: <c>dotnet-trace collect --profile cpu-sampling
    /// --format speedscope -o blake3-profile.speedscope.json
    /// -- dotnet run -c Release --no-build --project ... --
    /// --blake3-hotloop 2000</c> launches the hot-loop driver and
    /// attaches a CPU sampler from start.
    /// </para>
    /// </remarks>
    public static void Main(string[] args)
    {
        if(args.Length >= 1 && args[0] == "--blake3-hotloop")
        {
            int iterations = args.Length >= 2
                ? int.Parse(args[1], CultureInfo.InvariantCulture)
                : 2000;
            RunBlake3HotLoop(iterations);
            return;
        }

        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }


    /// <summary>
    /// Tight loop that hashes a 1 MiB buffer through
    /// <see cref="Lumoin.Veridical.Hashing.Blake3.Hash"/> repeatedly.
    /// Designed as a stable target for <c>dotnet-trace</c> CPU sampling.
    /// </summary>
    private static void RunBlake3HotLoop(int iterations)
    {
        byte[] input = new byte[1024 * 1024];
        new Random(0x5EED5EED).NextBytes(input);
        byte[] output = new byte[32];

        //Warm up so the JIT settles before sampling starts.
        for(int i = 0; i < 32; i++)
        {
            Lumoin.Veridical.Hashing.Blake3.Hash(input, output);
        }

        Stopwatch stopwatch = Stopwatch.StartNew();
        for(int i = 0; i < iterations; i++)
        {
            Lumoin.Veridical.Hashing.Blake3.Hash(input, output);
        }
        stopwatch.Stop();

        double avgMs = stopwatch.Elapsed.TotalMilliseconds / iterations;
        double throughputMbPerSec = (iterations * 1.0) / stopwatch.Elapsed.TotalSeconds;
        Console.WriteLine(
            string.Format(
                CultureInfo.InvariantCulture,
                "Blake3HotLoop: {0} iterations of 1 MiB, wall {1:F3}s, avg {2:F3}ms/op, {3:F0} hashes/sec",
                iterations,
                stopwatch.Elapsed.TotalSeconds,
                avgMs,
                throughputMbPerSec));
    }
}