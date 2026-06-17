using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// The G1 backend delegates the protocol test harnesses share. The
/// multi-scalar multiplication is the caching Pippenger backend — one cache
/// across the whole suite, so the commitment-key generator sets that recur
/// in every Hyrax, Pedersen, IPA, and Bulletproofs test decode exactly once
/// per run. Byte-identical to the naive reference (the same group element,
/// the same canonical encoding), which the agreement gates in
/// <c>Bls12Curve381PippengerG1BackendTests</c> pin; tests that compare MSM
/// implementations against each other keep wiring the reference explicitly.
/// </summary>
internal static class TestG1Backends
{
    /// <summary>The shared caching Pippenger BLS12-381 multi-scalar multiplication.</summary>
    public static G1MultiScalarMultiplyDelegate Bls12Curve381Msm { get; } = Bls12Curve381PippengerG1Backend.CreateCachingMultiScalarMultiply();

    /// <summary>The shared caching Pippenger BN254 multi-scalar multiplication.</summary>
    public static G1MultiScalarMultiplyDelegate Bn254Msm { get; } = Bn254PippengerG1Backend.CreateCachingMultiScalarMultiply();
}
