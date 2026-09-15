using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Longfellow;
using Lumoin.Veridical.Tests.TestInfrastructure;
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
/// <remarks>
/// With no per-ISA backend, seven getters throw the facade's documented exception and
/// message, while <c>GetBatchMultiply</c> returns the serial fallback. Direct serial tests
/// exercise arithmetic, exact buffer lengths, and operation counts on every host.
/// </remarks>
[TestClass]
internal sealed class SimdScalarBackendDispatchTests
{
    /// <summary>An empty batch exercises the no-element path with empty spans and no rentals.</summary>
    private const int EmptyCount = 0;

    /// <summary>A single element exercises the smallest nonempty serial batch.</summary>
    private const int SingleCount = 1;

    /// <summary>Three elements are not a lane multiple and stop before a full AVX2 group.</summary>
    private const int BeforeQuartetCount = 3;

    /// <summary>Four elements form one AVX2 lane group and fix the length-rejection count.</summary>
    private const int QuartetCount = 4;

    /// <summary>Five elements are not a lane multiple and extend past one AVX2 group.</summary>
    private const int AfterQuartetCount = 5;

    /// <summary>Eight elements form two AVX2 lane groups.</summary>
    private const int TwoQuartetCount = 8;

    /// <summary>Identifies the left operand as the only mis-sized buffer.</summary>
    private const int LeftBuffer = 0;

    /// <summary>Identifies the right operand as the only mis-sized buffer.</summary>
    private const int RightBuffer = 1;

    /// <summary>Identifies the destination as the only mis-sized buffer.</summary>
    private const int ResultBuffer = 2;

    /// <summary>Selects a reproducible full-width left scalar stream.</summary>
    private const int LeftFillSalt = 17;

    /// <summary>Selects a distinct full-width right scalar stream.</summary>
    private const int RightFillSalt = 29;

    /// <summary>Marks unwritten result bytes so a skipped element cannot rely on stack contents.</summary>
    private const byte ResultSentinel = 0xA5;

    /// <summary>The exact unsupported-host message identifies the Bn254 facade.</summary>
    private const string Bn254NoBackendMessage =
        "No SIMD scalar backend is supported on this host. AVX-512F, AVX2 (Intel/AMD x64), AArch64 NEON (ARM 64-bit), and WebAssembly PackedSimd are the supported sets. Check Bn254SimdScalarBackend.IsSupported before requesting a delegate.";

    /// <summary>The exact unsupported-host message identifies the Bls12Curve381 facade.</summary>
    private const string Bls12Curve381NoBackendMessage =
        "No SIMD scalar backend is supported on this host. AVX-512F, AVX2 (Intel/AMD x64), AArch64 NEON (ARM 64-bit), and WebAssembly PackedSimd are the supported sets. Check Bls12Curve381SimdScalarBackend.IsSupported before requesting a delegate.";


    /// <summary>Checks the BN254 serial fallback against reference batch multiplication on every host.</summary>
    /// <param name="count">Number of canonical scalar pairs spanning empty, single, partial, and full lane groups.</param>
    [TestMethod]
    [DataRow(EmptyCount)]
    [DataRow(SingleCount)]
    [DataRow(BeforeQuartetCount)]
    [DataRow(QuartetCount)]
    [DataRow(AfterQuartetCount)]
    [DataRow(TwoQuartetCount)]
    public void Bn254SerialBatchMultiplyMatchesTheReference(int count)
    {
        AssertSerialBatchMultiplyMatchesReference(
            Bn254SimdScalarBackend.BatchMultiply,
            Bn254BigIntegerScalarReference.GetBatchMultiply(),
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254,
            count);
    }


    /// <summary>Checks each BN254 serial buffer length independently and preserves the count in the error message.</summary>
    /// <param name="misSizedBuffer">The only buffer whose length differs from four scalar slots.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Bn254SerialBatchMultiplyRejectsMisSizedBuffers(int misSizedBuffer)
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => InvokeSerialBatchMultiplyWithMisSizedBuffer(
                Bn254SimdScalarBackend.BatchMultiply, CurveParameterSet.Bn254, misSizedBuffer));
        Assert.Contains($"count = {QuartetCount}", exception.Message);
    }


    /// <summary>Checks that one BN254 serial batch call counts every element and restores global telemetry switches.</summary>
    [TestMethod]
    [DoNotParallelize]
    public void Bn254SerialBatchMultiplyCountsEveryElement()
    {
        AssertSerialBatchMultiplyCountsEveryElement(
            Bn254SimdScalarBackend.BatchMultiply,
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254);
    }


    /// <summary>Checks the BLS12-381 serial fallback against reference batch multiplication on every host.</summary>
    /// <param name="count">Number of canonical scalar pairs spanning empty, single, partial, and full lane groups.</param>
    [TestMethod]
    [DataRow(EmptyCount)]
    [DataRow(SingleCount)]
    [DataRow(BeforeQuartetCount)]
    [DataRow(QuartetCount)]
    [DataRow(AfterQuartetCount)]
    [DataRow(TwoQuartetCount)]
    public void Bls12Curve381SerialBatchMultiplyMatchesTheReference(int count)
    {
        AssertSerialBatchMultiplyMatchesReference(
            Bls12Curve381SimdScalarBackend.BatchMultiply,
            Bls12Curve381BigIntegerScalarReference.GetBatchMultiply(),
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381,
            count);
    }


    /// <summary>Checks each BLS12-381 serial buffer length independently and preserves the count in the error message.</summary>
    /// <param name="misSizedBuffer">The only buffer whose length differs from four scalar slots.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Bls12Curve381SerialBatchMultiplyRejectsMisSizedBuffers(int misSizedBuffer)
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => InvokeSerialBatchMultiplyWithMisSizedBuffer(
                Bls12Curve381SimdScalarBackend.BatchMultiply, CurveParameterSet.Bls12Curve381, misSizedBuffer));
        Assert.Contains($"count = {QuartetCount}", exception.Message);
    }


    /// <summary>Checks that one BLS12-381 serial batch call counts every element and restores global telemetry switches.</summary>
    [TestMethod]
    [DoNotParallelize]
    public void Bls12Curve381SerialBatchMultiplyCountsEveryElement()
    {
        AssertSerialBatchMultiplyCountsEveryElement(
            Bls12Curve381SimdScalarBackend.BatchMultiply,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381);
    }


    /// <summary>Compares every output byte for deterministic canonical inputs, using empty spans for an empty batch.</summary>
    /// <param name="serialMultiply">The directly exercised serial fallback.</param>
    /// <param name="referenceMultiply">The curve's independent reference batch multiply.</param>
    /// <param name="reduce">The reference reduction used to fill canonical operands.</param>
    /// <param name="curve">Curve identity for arithmetic and telemetry.</param>
    /// <param name="count">Number of scalar pairs; the data rows bound stack use to two AVX2 groups.</param>
    private static void AssertSerialBatchMultiplyMatchesReference(
        ScalarBatchMultiplyDelegate serialMultiply,
        ScalarBatchMultiplyDelegate referenceMultiply,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        int count)
    {
        int byteCount = count * Scalar.SizeBytes;
        Span<byte> left = count is EmptyCount ? Span<byte>.Empty : stackalloc byte[byteCount];
        Span<byte> right = count is EmptyCount ? Span<byte>.Empty : stackalloc byte[byteCount];
        Span<byte> actual = count is EmptyCount ? Span<byte>.Empty : stackalloc byte[byteCount];
        Span<byte> expected = count is EmptyCount ? Span<byte>.Empty : stackalloc byte[byteCount];
        DeterministicScalarFill.FillCanonical(left, LeftFillSalt, reduce, curve);
        DeterministicScalarFill.FillCanonical(right, RightFillSalt, reduce, curve);
        actual.Fill(ResultSentinel);
        expected.Clear();

        serialMultiply(left, right, actual, count, curve);
        referenceMultiply(left, right, expected, count, curve);

        Assert.IsTrue(actual.SequenceEqual(expected), $"Serial batch multiplication must match the reference for count = {count}.");
    }


    /// <summary>Creates spans inside the throwing call with only the selected buffer mis-sized.</summary>
    /// <param name="serialMultiply">The directly exercised serial fallback.</param>
    /// <param name="curve">Curve identity passed to the fallback.</param>
    /// <param name="misSizedBuffer">Selects a short left operand, long right operand, or short destination.</param>
    private static void InvokeSerialBatchMultiplyWithMisSizedBuffer(
        ScalarBatchMultiplyDelegate serialMultiply,
        CurveParameterSet curve,
        int misSizedBuffer)
    {
        //One missing or extra element isolates each exact-length predicate at a fixed four-element count.
        const int ExactBytes = QuartetCount * Scalar.SizeBytes;
        const int ShortBytes = ExactBytes - Scalar.SizeBytes;
        const int LongBytes = ExactBytes + Scalar.SizeBytes;
        Span<byte> left = stackalloc byte[misSizedBuffer is LeftBuffer ? ShortBytes : ExactBytes];
        Span<byte> right = stackalloc byte[misSizedBuffer is RightBuffer ? LongBytes : ExactBytes];
        Span<byte> result = stackalloc byte[misSizedBuffer is ResultBuffer ? ShortBytes : ExactBytes];
        left.Clear();
        right.Clear();
        result.Fill(ResultSentinel);

        serialMultiply(left, right, result, QuartetCount, curve);
    }


    /// <summary>Measures one five-element serial call in isolation and restores counting and observing in a finally block.</summary>
    /// <param name="serialMultiply">The directly exercised serial fallback.</param>
    /// <param name="reduce">The reference reduction used before the measurement window.</param>
    /// <param name="curve">The facade's curve identity passed to its operation counter.</param>
    private static void AssertSerialBatchMultiplyCountsEveryElement(
        ScalarBatchMultiplyDelegate serialMultiply,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve)
    {
        bool wasCountingEnabled = CryptographicOperationCounters.IsCountingEnabled;
        bool wasObservingEnabled = CryptographicOperationCounters.IsObservingEnabled;
        try
        {
            CryptographicOperationCounters.IsCountingEnabled = false;
            CryptographicOperationCounters.IsObservingEnabled = false;
            //Five elements distinguish per-element counting from one call or one four-lane group.
            const int TelemetryCount = AfterQuartetCount;
            const int TelemetryBytes = TelemetryCount * Scalar.SizeBytes;
            Span<byte> left = stackalloc byte[TelemetryBytes];
            Span<byte> right = stackalloc byte[TelemetryBytes];
            Span<byte> result = stackalloc byte[TelemetryBytes];
            DeterministicScalarFill.FillCanonical(left, LeftFillSalt, reduce, curve);
            DeterministicScalarFill.FillCanonical(right, RightFillSalt, reduce, curve);

            //Only the directly owned serial call contributes inside the measurement window.
            CryptographicOperationCounters.IsCountingEnabled = true;
            CryptographicOperationCounters.Reset();
            long before = CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiply);
            serialMultiply(left, right, result, TelemetryCount, curve);
            long after = CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiply);

            Assert.AreEqual((long)TelemetryCount, after - before);
        }
        finally
        {
            CryptographicOperationCounters.Reset();
            CryptographicOperationCounters.IsCountingEnabled = wasCountingEnabled;
            CryptographicOperationCounters.IsObservingEnabled = wasObservingEnabled;
        }
    }


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
    /// unsupported, all seven throwing getters preserve the exact exception message,
    /// and <c>GetBatchMultiply</c> returns the serial fallback delegate.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381FacadeSelectsTheDocumentedOrderBackend()
    {
        if(Bls12Curve381Expected is null)
        {
            Assert.IsFalse(Bls12Curve381SimdScalarBackend.IsSupported, "IsSupported must be false when no per-ISA backend is available.");
            PlatformNotSupportedException addException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetAdd());
            Assert.AreEqual(Bls12Curve381NoBackendMessage, addException.Message);
            PlatformNotSupportedException subtractException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetSubtract());
            Assert.AreEqual(Bls12Curve381NoBackendMessage, subtractException.Message);
            PlatformNotSupportedException batchAddException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetBatchAdd());
            Assert.AreEqual(Bls12Curve381NoBackendMessage, batchAddException.Message);
            PlatformNotSupportedException batchSubtractException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetBatchSubtract());
            Assert.AreEqual(Bls12Curve381NoBackendMessage, batchSubtractException.Message);
            PlatformNotSupportedException multiplyException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetMultiply());
            Assert.AreEqual(Bls12Curve381NoBackendMessage, multiplyException.Message);
            PlatformNotSupportedException negateException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetNegate());
            Assert.AreEqual(Bls12Curve381NoBackendMessage, negateException.Message);
            PlatformNotSupportedException invertException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bls12Curve381SimdScalarBackend.GetInvert());
            Assert.AreEqual(Bls12Curve381NoBackendMessage, invertException.Message);
            ScalarBatchMultiplyDelegate serialBatchMultiply = Bls12Curve381SimdScalarBackend.BatchMultiply;
            Assert.AreEqual(serialBatchMultiply, Bls12Curve381SimdScalarBackend.GetBatchMultiply());

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
    /// the four instruction sets, that the facade reports itself unsupported, all seven
    /// throwing getters preserve the exact exception message, and <c>GetBatchMultiply</c>
    /// returns the serial fallback delegate.
    /// </summary>
    [TestMethod]
    public void Bn254FacadeSelectsTheDocumentedOrderBackend()
    {
        if(Bn254Expected is null)
        {
            Assert.IsFalse(Bn254SimdScalarBackend.IsSupported, "IsSupported must be false when no per-ISA backend is available.");
            PlatformNotSupportedException addException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetAdd());
            Assert.AreEqual(Bn254NoBackendMessage, addException.Message);
            PlatformNotSupportedException subtractException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetSubtract());
            Assert.AreEqual(Bn254NoBackendMessage, subtractException.Message);
            PlatformNotSupportedException batchAddException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetBatchAdd());
            Assert.AreEqual(Bn254NoBackendMessage, batchAddException.Message);
            PlatformNotSupportedException batchSubtractException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetBatchSubtract());
            Assert.AreEqual(Bn254NoBackendMessage, batchSubtractException.Message);
            PlatformNotSupportedException multiplyException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetMultiply());
            Assert.AreEqual(Bn254NoBackendMessage, multiplyException.Message);
            PlatformNotSupportedException negateException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetNegate());
            Assert.AreEqual(Bn254NoBackendMessage, negateException.Message);
            PlatformNotSupportedException invertException = Assert.ThrowsExactly<PlatformNotSupportedException>(
                () => Bn254SimdScalarBackend.GetInvert());
            Assert.AreEqual(Bn254NoBackendMessage, invertException.Message);
            ScalarBatchMultiplyDelegate serialBatchMultiply = Bn254SimdScalarBackend.BatchMultiply;
            Assert.AreEqual(serialBatchMultiply, Bn254SimdScalarBackend.GetBatchMultiply());

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
