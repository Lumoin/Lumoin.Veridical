using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// Environment-aware scalar backends for the test suite: the public managed
/// composition roots (<see cref="Bls12Curve381ManagedScalarBackend"/> /
/// <see cref="Bn254ManagedScalarBackend"/>), cached once, so protocol tests can pull
/// SIMD-accelerated field-operation delegates on hosts that support SIMD and fall
/// back to the BigInteger reference elsewhere — instead of hard-wiring the BigInteger
/// reference directly.
/// </summary>
/// <remarks>
/// <para>
/// The delegates are byte-identical to the BigInteger reference (the per-ISA
/// agreement sweeps gate that), so swapping a protocol test from the reference to one
/// of these bundles changes timing, never results — byte-pinned fixtures stay green.
/// Use this where a test wants the fastest correct arithmetic available; keep the
/// explicit <c>Bls12Curve381BigIntegerScalarReference</c> wiring where a test is
/// specifically about the reference itself (e.g. the agreement sweeps).
/// </para>
/// <para>
/// The bundles are <see cref="System.IDisposable"/> but own no native resource (their
/// owned-resource is null), so the never-disposed static instances leak nothing.
/// </para>
/// </remarks>
internal static class TestScalarBackends
{
    /// <summary>The BLS12-381 scalar backend bundle: SIMD field ops when the host supports them, BigInteger reference otherwise.</summary>
    public static ScalarArithmeticBackend Bls12Curve381 { get; } = Bls12Curve381ManagedScalarBackend.Create();

    /// <summary>The BN254 scalar backend bundle: SIMD field ops when the host supports them, BigInteger reference otherwise.</summary>
    public static ScalarArithmeticBackend Bn254 { get; } = Bn254ManagedScalarBackend.Create();

    /// <summary>The BLS12-381 BigInteger reference bundle: the correctness baseline with the batch operations as loops over the single-element delegates.</summary>
    public static ScalarArithmeticBackend Bls12Curve381Reference { get; } = new(
        CurveParameterSet.Bls12Curve381,
        Bls12Curve381BigIntegerScalarReference.GetReduce(),
        Bls12Curve381BigIntegerScalarReference.GetAdd(),
        Bls12Curve381BigIntegerScalarReference.GetSubtract(),
        Bls12Curve381BigIntegerScalarReference.GetMultiply(),
        Bls12Curve381BigIntegerScalarReference.GetNegate(),
        Bls12Curve381BigIntegerScalarReference.GetInvert(),
        Bls12Curve381BigIntegerScalarReference.GetRandom(),
        Bls12Curve381BigIntegerScalarReference.GetBatchAdd(),
        Bls12Curve381BigIntegerScalarReference.GetBatchSubtract(),
        Bls12Curve381BigIntegerScalarReference.GetBatchMultiply(),
        Bls12Curve381BigIntegerScalarReference.GetHashToScalar());

    /// <summary>The BN254 BigInteger reference bundle.</summary>
    public static ScalarArithmeticBackend Bn254Reference { get; } = new(
        CurveParameterSet.Bn254,
        Bn254BigIntegerScalarReference.GetReduce(),
        Bn254BigIntegerScalarReference.GetAdd(),
        Bn254BigIntegerScalarReference.GetSubtract(),
        Bn254BigIntegerScalarReference.GetMultiply(),
        Bn254BigIntegerScalarReference.GetNegate(),
        Bn254BigIntegerScalarReference.GetInvert(),
        Bn254BigIntegerScalarReference.GetRandom(),
        Bn254BigIntegerScalarReference.GetBatchAdd(),
        Bn254BigIntegerScalarReference.GetBatchSubtract(),
        Bn254BigIntegerScalarReference.GetBatchMultiply(),
        hashToScalar: null);
}
