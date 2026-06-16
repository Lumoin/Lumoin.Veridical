using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;

namespace Lumoin.Veridical.Benchmarks.Commitments.Ligero;

/// <summary>
/// End-to-end timing (and allocation) of a Ligero prove + verify over Fp256 for
/// a representative elliptic-curve circuit — a chain of complete projective
/// additions of varying length — to give the wall-time/alloc denominator the
/// encoder and field-op microbenchmarks are attributed against. Kept small
/// (chain length 1–4) so BenchmarkDotNet's throughput pilot stays tractable; the
/// realistic-scale ladder is measured once by the <c>--ligero-attribution</c>
/// driver instead.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 1, iterationCount: 5)]
public class LigeroProveBenchmarks
{
    //Number of chained complete additions; each is ~30 wires + a dozen
    //quadratics, so this sweeps the prover's row count.
    [Params(1, 4)]
    public int Additions { get; set; }

    private ScalarAddDelegate add = null!;
    private ScalarSubtractDelegate subtract = null!;
    private ScalarMultiplyDelegate multiply = null!;
    private ScalarInvertDelegate invert = null!;
    private ScalarReduceDelegate reduce = null!;


    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        add = P256BaseFieldReference.GetAdd();
        subtract = P256BaseFieldReference.GetSubtract();
        multiply = P256BaseFieldReference.GetMultiply();
        invert = P256BaseFieldReference.GetInvert();
        reduce = P256BaseFieldReference.GetReduce();
    }


    [Benchmark(Description = "Prove (chained complete-add)")]
    public bool ProveAndVerify()
    {
        LigeroConstraintSystemBuilder builder = LigeroFp256Harness.BuildChainedAddition(Additions, add, subtract, multiply, invert, reduce);
        using LigeroProof proof = LigeroFp256Harness.Prove(builder, add, subtract, multiply, invert, reduce);

        return LigeroFp256Harness.Verify(builder, proof, add, subtract, multiply, invert, reduce);
    }
}
