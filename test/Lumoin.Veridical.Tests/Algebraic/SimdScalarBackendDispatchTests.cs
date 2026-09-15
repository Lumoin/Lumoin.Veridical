using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Longfellow;
using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.Wasm;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Pins which per-ISA backend each SIMD dispatch facade selects on the host this test
/// runs on. Every facade orders its capability checks the same way
/// (<see cref="Avx512F.IsSupported"/> combined with <see cref="Vector512.IsHardwareAccelerated"/>,
/// then <see cref="Avx2.IsSupported"/>, then <see cref="AdvSimd.Arm64.IsSupported"/>, then
/// <see cref="PackedSimd.IsSupported"/>); this class re-derives that same order independently
/// with a switch expression and asserts the facade's own selection agrees with it. The AVX-512
/// arm requires both predicates, so a host that reports AVX-512F but not
/// <see cref="Vector512.IsHardwareAccelerated"/> falls through to AVX2 here and in the facades
/// alike. The no-backend branch is reachable on an x64 host by starting the runner with
/// <c>DOTNET_EnableAVX2=0</c>, which withdraws AVX-512 as well because the runtime's AVX-512
/// support builds on AVX2; <c>DOTNET_EnableAVX512=0</c> alone leaves the AVX2 arm selected.
/// </summary>
[TestClass]
internal sealed class SimdScalarBackendDispatchTests
{
    /// <summary>
    /// One per-ISA backend's full delegate set, captured so a facade's eight <c>Get*</c>
    /// results can be compared against the backend the capability order selects in one
    /// shot. Two delegates over the same static method are equal under
    /// <see cref="Delegate.Equals(object?)"/>, which is what <c>Assert.AreEqual</c>
    /// relies on below.
    /// </summary>
    /// <param name="Add">The delegate the backend's <c>GetAdd</c> returns.</param>
    /// <param name="Subtract">The delegate the backend's <c>GetSubtract</c> returns.</param>
    /// <param name="BatchAdd">The delegate the backend's <c>GetBatchAdd</c> returns.</param>
    /// <param name="BatchSubtract">The delegate the backend's <c>GetBatchSubtract</c> returns.</param>
    /// <param name="Multiply">The delegate the backend's <c>GetMultiply</c> returns.</param>
    /// <param name="Negate">The delegate the backend's <c>GetNegate</c> returns.</param>
    /// <param name="Invert">The delegate the backend's <c>GetInvert</c> returns.</param>
    /// <param name="BatchMultiply">The delegate the backend's <c>GetBatchMultiply</c> returns.</param>
    private sealed record BackendDelegateSet(
        ScalarAddDelegate Add,
        ScalarSubtractDelegate Subtract,
        ScalarBatchAddDelegate BatchAdd,
        ScalarBatchSubtractDelegate BatchSubtract,
        ScalarMultiplyDelegate Multiply,
        ScalarNegateDelegate Negate,
        ScalarInvertDelegate Invert,
        ScalarBatchMultiplyDelegate BatchMultiply);


    /// <summary>
    /// The BLS12-381 per-ISA backend the documented capability order selects on this host,
    /// or <see langword="null"/> when none of the four instruction sets is supported here.
    /// </summary>
    private static BackendDelegateSet? Bls12Curve381Expected { get; } =
        (Avx512F.IsSupported && Vector512.IsHardwareAccelerated, Avx2.IsSupported, AdvSimd.Arm64.IsSupported, PackedSimd.IsSupported) switch
        {
            (true, _, _, _) => new BackendDelegateSet(
                Bls12Curve381Avx512ScalarBackend.GetAdd(),
                Bls12Curve381Avx512ScalarBackend.GetSubtract(),
                Bls12Curve381Avx512ScalarBackend.GetBatchAdd(),
                Bls12Curve381Avx512ScalarBackend.GetBatchSubtract(),
                Bls12Curve381Avx512ScalarBackend.GetMultiply(),
                Bls12Curve381Avx512ScalarBackend.GetNegate(),
                Bls12Curve381Avx512ScalarBackend.GetInvert(),
                Bls12Curve381Avx512ScalarBackend.GetBatchMultiply()),
            (false, true, _, _) => new BackendDelegateSet(
                Bls12Curve381Avx2ScalarBackend.GetAdd(),
                Bls12Curve381Avx2ScalarBackend.GetSubtract(),
                Bls12Curve381Avx2ScalarBackend.GetBatchAdd(),
                Bls12Curve381Avx2ScalarBackend.GetBatchSubtract(),
                Bls12Curve381Avx2ScalarBackend.GetMultiply(),
                Bls12Curve381Avx2ScalarBackend.GetNegate(),
                Bls12Curve381Avx2ScalarBackend.GetInvert(),
                Bls12Curve381Avx2ScalarBackend.GetBatchMultiply()),
            (false, false, true, _) => new BackendDelegateSet(
                Bls12Curve381NeonScalarBackend.GetAdd(),
                Bls12Curve381NeonScalarBackend.GetSubtract(),
                Bls12Curve381NeonScalarBackend.GetBatchAdd(),
                Bls12Curve381NeonScalarBackend.GetBatchSubtract(),
                Bls12Curve381NeonScalarBackend.GetMultiply(),
                Bls12Curve381NeonScalarBackend.GetNegate(),
                Bls12Curve381NeonScalarBackend.GetInvert(),
                Bls12Curve381NeonScalarBackend.GetBatchMultiply()),
            (false, false, false, true) => new BackendDelegateSet(
                Bls12Curve381WasmScalarBackend.GetAdd(),
                Bls12Curve381WasmScalarBackend.GetSubtract(),
                Bls12Curve381WasmScalarBackend.GetBatchAdd(),
                Bls12Curve381WasmScalarBackend.GetBatchSubtract(),
                Bls12Curve381WasmScalarBackend.GetMultiply(),
                Bls12Curve381WasmScalarBackend.GetNegate(),
                Bls12Curve381WasmScalarBackend.GetInvert(),
                Bls12Curve381WasmScalarBackend.GetBatchMultiply()),
            _ => null,
        };


    /// <summary>
    /// The BN254 per-ISA backend the documented capability order selects on this host, or
    /// <see langword="null"/> when none of the four instruction sets is supported here.
    /// </summary>
    private static BackendDelegateSet? Bn254Expected { get; } =
        (Avx512F.IsSupported && Vector512.IsHardwareAccelerated, Avx2.IsSupported, AdvSimd.Arm64.IsSupported, PackedSimd.IsSupported) switch
        {
            (true, _, _, _) => new BackendDelegateSet(
                Bn254Avx512ScalarBackend.GetAdd(),
                Bn254Avx512ScalarBackend.GetSubtract(),
                Bn254Avx512ScalarBackend.GetBatchAdd(),
                Bn254Avx512ScalarBackend.GetBatchSubtract(),
                Bn254Avx512ScalarBackend.GetMultiply(),
                Bn254Avx512ScalarBackend.GetNegate(),
                Bn254Avx512ScalarBackend.GetInvert(),
                Bn254Avx512ScalarBackend.GetBatchMultiply()),
            (false, true, _, _) => new BackendDelegateSet(
                Bn254Avx2ScalarBackend.GetAdd(),
                Bn254Avx2ScalarBackend.GetSubtract(),
                Bn254Avx2ScalarBackend.GetBatchAdd(),
                Bn254Avx2ScalarBackend.GetBatchSubtract(),
                Bn254Avx2ScalarBackend.GetMultiply(),
                Bn254Avx2ScalarBackend.GetNegate(),
                Bn254Avx2ScalarBackend.GetInvert(),
                Bn254Avx2ScalarBackend.GetBatchMultiply()),
            (false, false, true, _) => new BackendDelegateSet(
                Bn254NeonScalarBackend.GetAdd(),
                Bn254NeonScalarBackend.GetSubtract(),
                Bn254NeonScalarBackend.GetBatchAdd(),
                Bn254NeonScalarBackend.GetBatchSubtract(),
                Bn254NeonScalarBackend.GetMultiply(),
                Bn254NeonScalarBackend.GetNegate(),
                Bn254NeonScalarBackend.GetInvert(),
                Bn254NeonScalarBackend.GetBatchMultiply()),
            (false, false, false, true) => new BackendDelegateSet(
                Bn254WasmScalarBackend.GetAdd(),
                Bn254WasmScalarBackend.GetSubtract(),
                Bn254WasmScalarBackend.GetBatchAdd(),
                Bn254WasmScalarBackend.GetBatchSubtract(),
                Bn254WasmScalarBackend.GetMultiply(),
                Bn254WasmScalarBackend.GetNegate(),
                Bn254WasmScalarBackend.GetInvert(),
                Bn254WasmScalarBackend.GetBatchMultiply()),
            _ => null,
        };


    /// <summary>
    /// Asserts <see cref="Bls12Curve381SimdScalarBackend"/>'s eight <c>Get*</c> methods each
    /// return the delegate from the backend <see cref="Bls12Curve381Expected"/> names, or, on a
    /// host with none of the four instruction sets, that the facade reports itself
    /// unsupported and throws from <c>GetAdd</c> instead. The unsupported branch asserts only
    /// <c>GetAdd</c>: <c>GetBatchMultiply</c> alone among the eight does not throw there — it
    /// falls back to a private serial CIOS loop so callers without a request-time backend
    /// still get a working (if unbatched) delegate — so it is not part of the common-order
    /// contract this test pins.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381FacadeSelectsTheDocumentedOrderBackend()
    {
        if(Bls12Curve381Expected is null)
        {
            Assert.IsFalse(Bls12Curve381SimdScalarBackend.IsSupported, "IsSupported must be false when no per-ISA backend is available.");
            Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetAdd(),
                "GetAdd must throw PlatformNotSupportedException when no per-ISA backend is available.");

            return;
        }

        Assert.IsTrue(Bls12Curve381SimdScalarBackend.IsSupported, "IsSupported must be true once a per-ISA backend is available.");
        Assert.AreEqual(Bls12Curve381Expected.Add, Bls12Curve381SimdScalarBackend.GetAdd(), "GetAdd must return the selected backend's Add.");
        Assert.AreEqual(Bls12Curve381Expected.Subtract, Bls12Curve381SimdScalarBackend.GetSubtract(), "GetSubtract must return the selected backend's Subtract.");
        Assert.AreEqual(Bls12Curve381Expected.BatchAdd, Bls12Curve381SimdScalarBackend.GetBatchAdd(), "GetBatchAdd must return the selected backend's BatchAdd.");
        Assert.AreEqual(Bls12Curve381Expected.BatchSubtract, Bls12Curve381SimdScalarBackend.GetBatchSubtract(), "GetBatchSubtract must return the selected backend's BatchSubtract.");
        Assert.AreEqual(Bls12Curve381Expected.Multiply, Bls12Curve381SimdScalarBackend.GetMultiply(), "GetMultiply must return the selected backend's Multiply.");
        Assert.AreEqual(Bls12Curve381Expected.Negate, Bls12Curve381SimdScalarBackend.GetNegate(), "GetNegate must return the selected backend's Negate.");
        Assert.AreEqual(Bls12Curve381Expected.Invert, Bls12Curve381SimdScalarBackend.GetInvert(), "GetInvert must return the selected backend's Invert.");
        Assert.AreEqual(Bls12Curve381Expected.BatchMultiply, Bls12Curve381SimdScalarBackend.GetBatchMultiply(), "GetBatchMultiply must return the selected backend's BatchMultiply.");
    }


    /// <summary>
    /// The BN254 mirror of <see cref="Bls12Curve381FacadeSelectsTheDocumentedOrderBackend"/>:
    /// asserts <see cref="Bn254SimdScalarBackend"/>'s eight <c>Get*</c> methods each return the
    /// delegate from the backend <see cref="Bn254Expected"/> names, or, on a host with none of
    /// the four instruction sets, that the facade reports itself unsupported and throws from
    /// <c>GetAdd</c> instead.
    /// </summary>
    [TestMethod]
    public void Bn254FacadeSelectsTheDocumentedOrderBackend()
    {
        if(Bn254Expected is null)
        {
            Assert.IsFalse(Bn254SimdScalarBackend.IsSupported, "IsSupported must be false when no per-ISA backend is available.");
            Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetAdd(),
                "GetAdd must throw PlatformNotSupportedException when no per-ISA backend is available.");

            return;
        }

        Assert.IsTrue(Bn254SimdScalarBackend.IsSupported, "IsSupported must be true once a per-ISA backend is available.");
        Assert.AreEqual(Bn254Expected.Add, Bn254SimdScalarBackend.GetAdd(), "GetAdd must return the selected backend's Add.");
        Assert.AreEqual(Bn254Expected.Subtract, Bn254SimdScalarBackend.GetSubtract(), "GetSubtract must return the selected backend's Subtract.");
        Assert.AreEqual(Bn254Expected.BatchAdd, Bn254SimdScalarBackend.GetBatchAdd(), "GetBatchAdd must return the selected backend's BatchAdd.");
        Assert.AreEqual(Bn254Expected.BatchSubtract, Bn254SimdScalarBackend.GetBatchSubtract(), "GetBatchSubtract must return the selected backend's BatchSubtract.");
        Assert.AreEqual(Bn254Expected.Multiply, Bn254SimdScalarBackend.GetMultiply(), "GetMultiply must return the selected backend's Multiply.");
        Assert.AreEqual(Bn254Expected.Negate, Bn254SimdScalarBackend.GetNegate(), "GetNegate must return the selected backend's Negate.");
        Assert.AreEqual(Bn254Expected.Invert, Bn254SimdScalarBackend.GetInvert(), "GetInvert must return the selected backend's Invert.");
        Assert.AreEqual(Bn254Expected.BatchMultiply, Bn254SimdScalarBackend.GetBatchMultiply(), "GetBatchMultiply must return the selected backend's BatchMultiply.");
    }


    /// <summary>
    /// Asserts <see cref="LongfellowMdocBundles.Fp256BatchMontgomery"/> returns the AVX-512
    /// batch Montgomery multiply when <see cref="P256BaseFieldMontgomeryBatchBackendAvx512.IsSupported"/>
    /// and <see cref="Vector512.IsHardwareAccelerated"/> both hold, else the AVX2 twin's when
    /// that one is supported, else <see langword="null"/> — the two-backend, no-throw selector
    /// that is this method's own documented order, distinct from the four-ISA facades above.
    /// </summary>
    [TestMethod]
    public void Fp256BatchMontgomerySelectsTheDocumentedOrderBackend()
    {
        ScalarBatchMultiplyDelegate? expected = (P256BaseFieldMontgomeryBatchBackendAvx512.IsSupported && Vector512.IsHardwareAccelerated, P256BaseFieldMontgomeryBatchBackendAvx2.IsSupported) switch
        {
            (true, _) => P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery(),
            (false, true) => P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery(),
            _ => null,
        };

        Assert.AreEqual(
            expected,
            LongfellowMdocBundles.Fp256BatchMontgomery(),
            "Fp256BatchMontgomery must return the AVX-512 batch delegate when supported, else the AVX2 twin's, else null.");
    }
}
