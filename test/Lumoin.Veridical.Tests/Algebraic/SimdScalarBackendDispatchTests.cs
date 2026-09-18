using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Longfellow;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
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
/// That switch, or a host without AVX2, is also the only configuration in which the BN254,
/// BLS12-381, and Fp256 AVX2 kernels run their own refusal guards, and no dispatch path hands
/// an AVX2 delegate out there. The refusal tests therefore take each delegate from its kernel's
/// internal accessor, give it inputs that every other check in the kernel accepts, pin the
/// exact <see cref="PlatformNotSupportedException"/> message, and report Inconclusive wherever
/// AVX2 is present.
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

    /// <summary>The only byte value in a zero scalar, so any other byte shows an operand is nonzero.</summary>
    private const byte ZeroByte = 0;

    /// <summary>The exact unsupported-host message identifies the Bn254 facade.</summary>
    private const string Bn254NoBackendMessage =
        "No SIMD scalar backend is supported on this host. AVX-512F, AVX2 (Intel/AMD x64), AArch64 NEON (ARM 64-bit), and WebAssembly PackedSimd are the supported sets. Check Bn254SimdScalarBackend.IsSupported before requesting a delegate.";

    /// <summary>The exact unsupported-host message identifies the Bls12Curve381 facade.</summary>
    private const string Bls12Curve381NoBackendMessage =
        "No SIMD scalar backend is supported on this host. AVX-512F, AVX2 (Intel/AMD x64), AArch64 NEON (ARM 64-bit), and WebAssembly PackedSimd are the supported sets. Check Bls12Curve381SimdScalarBackend.IsSupported before requesting a delegate.";

    /// <summary>The exact unsupported-host message identifies the BN254 AVX2 kernel rather than the runtime's generic intrinsic refusal.</summary>
    private const string Bn254Avx2UnsupportedMessage =
        "Bn254Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.";

    /// <summary>The exact unsupported-host message identifies the BLS12-381 AVX2 kernel rather than the runtime's generic intrinsic refusal.</summary>
    private const string Bls12Curve381Avx2UnsupportedMessage =
        "Bls12Curve381Avx2ScalarBackend requires AVX2; check IsSupported before wiring it as a delegate.";

    /// <summary>The exact unsupported-host message identifies the Fp256 AVX2 batch kernel rather than the runtime's generic intrinsic refusal.</summary>
    private const string Fp256Avx2UnsupportedMessage =
        "P256BaseFieldMontgomeryBatchBackendAvx2 requires AVX2; check IsSupported before wiring it as a delegate.";

    /// <summary>Explains the skip where AVX2 is present, because the AVX2 kernels' refusal guards cannot run there.</summary>
    private const string Avx2PresentReason =
        "AVX2 is supported on this host; the refusal gate is exercised on hosts without AVX2 or under DOTNET_EnableAVX2=0.";


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


    /// <summary>
    /// Pins the BN254 AVX2 add kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because single-element add checks neither length nor value
    /// and each canonical operand fills exactly one slot; without the guard the call would fail
    /// later, inside an AVX2 blend, with the runtime's generic message.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2AddRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertBinaryOperationRefusesBeforeWriting(
            Bn254Avx2ScalarBackend.GetAdd().Invoke,
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BN254 AVX2 subtract kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because single-element subtract checks neither length nor
    /// value and each canonical operand fills exactly one slot; without the guard the call would
    /// fail later, inside an AVX2 blend, with the runtime's generic message.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2SubtractRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertBinaryOperationRefusesBeforeWriting(
            Bn254Avx2ScalarBackend.GetSubtract().Invoke,
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BN254 AVX2 multiply kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because single-element multiply checks neither length nor
    /// value and each canonical operand fills exactly one slot; without the guard the shared
    /// Montgomery multiply, which uses no intrinsics, would write the product and return.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2MultiplyRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertBinaryOperationRefusesBeforeWriting(
            Bn254Avx2ScalarBackend.GetMultiply().Invoke,
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BN254 AVX2 invert kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because the canonical operand fills exactly one slot and is
    /// nonzero, which keeps the zero-inverse rejection behind the guard silent; without the guard
    /// the shared Montgomery inversion, which uses no intrinsics, would write the inverse and return.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2InvertRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertUnaryOperationRefusesBeforeWriting(
            Bn254Avx2ScalarBackend.GetInvert().Invoke,
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BN254 AVX2 negate kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because negation checks neither length nor value and the
    /// canonical operand fills exactly one slot; without the guard the call would fail later,
    /// inside an AVX2 blend, with the runtime's generic message.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2NegateRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertUnaryOperationRefusesBeforeWriting(
            Bn254Avx2ScalarBackend.GetNegate().Invoke,
            Bn254BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BN254 AVX2 batch-add kernel's refusal where AVX2 is unavailable by its exact
    /// <see cref="PlatformNotSupportedException"/> message. Only the kernel's AVX2 guard can
    /// answer: an empty batch over empty spans has exactly the length the check behind the guard
    /// requires and leaves no quartet or tail element to run, so without the guard the call would
    /// return normally.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2BatchAddRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertEmptyBatchRefuses(
            Bn254Avx2ScalarBackend.GetBatchAdd().Invoke,
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BN254 AVX2 batch-subtract kernel's refusal where AVX2 is unavailable by its exact
    /// <see cref="PlatformNotSupportedException"/> message. Only the kernel's AVX2 guard can
    /// answer: an empty batch over empty spans has exactly the length the check behind the guard
    /// requires and leaves no quartet or tail element to run, so without the guard the call would
    /// return normally.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2BatchSubtractRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertEmptyBatchRefuses(
            Bn254Avx2ScalarBackend.GetBatchSubtract().Invoke,
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BN254 AVX2 batch-multiply kernel's refusal where AVX2 is unavailable by its exact
    /// <see cref="PlatformNotSupportedException"/> message. Only the kernel's AVX2 guard can
    /// answer: an empty batch over empty spans has exactly the length the check behind the guard
    /// requires and leaves no quartet or tail element to run, so without the guard the call would
    /// return normally.
    /// </summary>
    [TestMethod]
    public void Bn254Avx2BatchMultiplyRefusesLoudlyOffAvx2()
    {
        if(Bn254Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertEmptyBatchRefuses(
            Bn254Avx2ScalarBackend.GetBatchMultiply().Invoke,
            CurveParameterSet.Bn254,
            Bn254Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 add kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because single-element add checks neither length nor value
    /// and each canonical operand fills exactly one slot; without the guard the call would fail
    /// later, inside an AVX2 blend, with the runtime's generic message.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2AddRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertBinaryOperationRefusesBeforeWriting(
            Bls12Curve381Avx2ScalarBackend.GetAdd().Invoke,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 subtract kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because single-element subtract checks neither length nor
    /// value and each canonical operand fills exactly one slot; without the guard the call would
    /// fail later, inside an AVX2 blend, with the runtime's generic message.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2SubtractRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertBinaryOperationRefusesBeforeWriting(
            Bls12Curve381Avx2ScalarBackend.GetSubtract().Invoke,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 multiply kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because single-element multiply checks neither length nor
    /// value and each canonical operand fills exactly one slot; without the guard the shared
    /// Montgomery multiply, which uses no intrinsics, would write the product and return.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2MultiplyRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertBinaryOperationRefusesBeforeWriting(
            Bls12Curve381Avx2ScalarBackend.GetMultiply().Invoke,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 invert kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because the canonical operand fills exactly one slot and is
    /// nonzero, which keeps the zero-inverse rejection behind the guard silent; without the guard
    /// the shared Montgomery inversion, which uses no intrinsics, would write the inverse and return.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2InvertRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertUnaryOperationRefusesBeforeWriting(
            Bls12Curve381Avx2ScalarBackend.GetInvert().Invoke,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 negate kernel's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer, because negation checks neither length nor value and the
    /// canonical operand fills exactly one slot; without the guard the call would fail later,
    /// inside an AVX2 blend, with the runtime's generic message.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2NegateRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertUnaryOperationRefusesBeforeWriting(
            Bls12Curve381Avx2ScalarBackend.GetNegate().Invoke,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 batch-add kernel's refusal where AVX2 is unavailable by its exact
    /// <see cref="PlatformNotSupportedException"/> message. Only the kernel's AVX2 guard can
    /// answer: an empty batch over empty spans has exactly the length the check behind the guard
    /// requires and leaves no quartet or tail element to run, so without the guard the call would
    /// return normally.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2BatchAddRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertEmptyBatchRefuses(
            Bls12Curve381Avx2ScalarBackend.GetBatchAdd().Invoke,
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 batch-subtract kernel's refusal where AVX2 is unavailable by its
    /// exact <see cref="PlatformNotSupportedException"/> message. Only the kernel's AVX2 guard can
    /// answer: an empty batch over empty spans has exactly the length the check behind the guard
    /// requires and leaves no quartet or tail element to run, so without the guard the call would
    /// return normally.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2BatchSubtractRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertEmptyBatchRefuses(
            Bls12Curve381Avx2ScalarBackend.GetBatchSubtract().Invoke,
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the BLS12-381 AVX2 batch-multiply kernel's refusal where AVX2 is unavailable by its
    /// exact <see cref="PlatformNotSupportedException"/> message. Only the kernel's AVX2 guard can
    /// answer: an empty batch over empty spans has exactly the length the check behind the guard
    /// requires and leaves no quartet or tail element to run, so without the guard the call would
    /// return normally.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Avx2BatchMultiplyRefusesLoudlyOffAvx2()
    {
        if(Bls12Curve381Avx2ScalarBackend.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        AssertEmptyBatchRefuses(
            Bls12Curve381Avx2ScalarBackend.GetBatchMultiply().Invoke,
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381Avx2UnsupportedMessage);
    }


    /// <summary>
    /// Pins the Fp256 AVX2 batch Montgomery multiply's refusal where AVX2 is unavailable: the exact
    /// <see cref="PlatformNotSupportedException"/> message and an untouched destination. Only the
    /// kernel's AVX2 guard can answer: one element over exact one-slot buffers passes the length
    /// check behind the guard and stays below the four-lane quartet width, so without the guard the
    /// call would run only the scalar Montgomery tail, which uses no intrinsics, and write the
    /// Montgomery product. The specialized-reduce accessor enters the same guard.
    /// </summary>
    [TestMethod]
    public void Fp256Avx2BatchMultiplyMontgomeryRefusesLoudlyOffAvx2()
    {
        if(P256BaseFieldMontgomeryBatchBackendAvx2.IsSupported)
        {
            Assert.Inconclusive(Avx2PresentReason);
        }

        //One element stays below the quartet width, and one slot per buffer is the exact length the check behind the guard accepts.
        const int ExactBytes = SingleCount * Scalar.SizeBytes;
        ScalarReduceDelegate reduce = P256BaseFieldReference.GetReduce();
        using IMemoryOwner<byte> leftOwner = BaseMemoryPool.Shared.Rent(ExactBytes);
        using IMemoryOwner<byte> rightOwner = BaseMemoryPool.Shared.Rent(ExactBytes);
        using IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(ExactBytes);
        Memory<byte> left = leftOwner.Memory[..ExactBytes];
        Memory<byte> right = rightOwner.Memory[..ExactBytes];
        Memory<byte> result = resultOwner.Memory[..ExactBytes];
        DeterministicScalarFill.FillCanonical(left.Span, LeftFillSalt, reduce, CurveParameterSet.None);
        DeterministicScalarFill.FillCanonical(right.Span, RightFillSalt, reduce, CurveParameterSet.None);
        result.Span.Fill(ResultSentinel);
        ScalarBatchMultiplyDelegate batchMultiply = P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery();

        //Memory values can be captured; spans are created only inside the single throwing expression.
        PlatformNotSupportedException exception = Assert.ThrowsExactly<PlatformNotSupportedException>(
            () => batchMultiply(left.Span, right.Span, result.Span, SingleCount, CurveParameterSet.None));

        Assert.AreEqual(Fp256Avx2UnsupportedMessage, exception.Message);
        AssertDestinationHoldsSentinel(result.Span);
    }


    /// <summary>Common span signature for the AVX2 kernels' single-element add, subtract, and multiply.</summary>
    /// <param name="left">One canonical left operand.</param>
    /// <param name="right">One canonical right operand.</param>
    /// <param name="result">One destination slot.</param>
    /// <param name="curve">Field identity passed to the kernel.</param>
    private delegate void BinaryOperation(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> result, CurveParameterSet curve);


    /// <summary>Common span signature for the AVX2 kernels' single-element negate and invert.</summary>
    /// <param name="operand">One canonical operand.</param>
    /// <param name="result">One destination slot.</param>
    /// <param name="curve">Field identity passed to the kernel.</param>
    private delegate void UnaryOperation(ReadOnlySpan<byte> operand, Span<byte> result, CurveParameterSet curve);


    /// <summary>Common span signature for the AVX2 kernels' batch add, subtract, and multiply.</summary>
    /// <param name="left">Concatenated left operands.</param>
    /// <param name="right">Concatenated right operands.</param>
    /// <param name="result">Concatenated destination slots.</param>
    /// <param name="count">Number of canonical slots.</param>
    /// <param name="curve">Field identity passed to the kernel.</param>
    private delegate void BatchOperation(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> result, int count, CurveParameterSet curve);


    /// <summary>
    /// Calls a single-element two-operand kernel on canonical one-slot operands and pins its
    /// refusal: the exact exception type and message, and a destination that still holds the
    /// sentinel because the AVX2 guard precedes every write.
    /// </summary>
    /// <param name="operation">The kernel delegate taken from its backend's accessor.</param>
    /// <param name="reduce">The reference reduction used to fill canonical operands.</param>
    /// <param name="curve">Curve identity for the operands and the kernel.</param>
    /// <param name="expectedMessage">The kernel's exact refusal text.</param>
    private static void AssertBinaryOperationRefusesBeforeWriting(
        BinaryOperation operation,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        string expectedMessage)
    {
        using IMemoryOwner<byte> leftOwner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        using IMemoryOwner<byte> rightOwner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        using IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Memory<byte> left = leftOwner.Memory[..Scalar.SizeBytes];
        Memory<byte> right = rightOwner.Memory[..Scalar.SizeBytes];
        Memory<byte> result = resultOwner.Memory[..Scalar.SizeBytes];
        DeterministicScalarFill.FillCanonical(left.Span, LeftFillSalt, reduce, curve);
        DeterministicScalarFill.FillCanonical(right.Span, RightFillSalt, reduce, curve);
        result.Span.Fill(ResultSentinel);

        //Memory values can be captured; spans are created only inside the single throwing expression.
        PlatformNotSupportedException exception = Assert.ThrowsExactly<PlatformNotSupportedException>(
            () => operation(left.Span, right.Span, result.Span, curve));

        Assert.AreEqual(expectedMessage, exception.Message);
        AssertDestinationHoldsSentinel(result.Span);
    }


    /// <summary>
    /// Calls a single-element one-operand kernel on a nonzero canonical one-slot operand and pins
    /// its refusal: the exact exception type and message, and a destination that still holds the
    /// sentinel because the AVX2 guard precedes every write.
    /// </summary>
    /// <param name="operation">The kernel delegate taken from its backend's accessor.</param>
    /// <param name="reduce">The reference reduction used to fill the canonical operand.</param>
    /// <param name="curve">Curve identity for the operand and the kernel.</param>
    /// <param name="expectedMessage">The kernel's exact refusal text.</param>
    private static void AssertUnaryOperationRefusesBeforeWriting(
        UnaryOperation operation,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        string expectedMessage)
    {
        using IMemoryOwner<byte> operandOwner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        using IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Memory<byte> operand = operandOwner.Memory[..Scalar.SizeBytes];
        Memory<byte> result = resultOwner.Memory[..Scalar.SizeBytes];
        DeterministicScalarFill.FillCanonical(operand.Span, LeftFillSalt, reduce, curve);
        result.Span.Fill(ResultSentinel);

        //Every filled 32-bit word is odd before reduction, and every multiple of the BN254 or BLS12-381
        //scalar modulus below 2^256 has an even word, so no zero-inverse rejection can answer instead of the guard.
        Assert.IsTrue(operand.Span.ContainsAnyExcept(ZeroByte), "The operand must be nonzero so only the AVX2 guard can refuse.");

        //Memory values can be captured; spans are created only inside the single throwing expression.
        PlatformNotSupportedException exception = Assert.ThrowsExactly<PlatformNotSupportedException>(
            () => operation(operand.Span, result.Span, curve));

        Assert.AreEqual(expectedMessage, exception.Message);
        AssertDestinationHoldsSentinel(result.Span);
    }


    /// <summary>
    /// Calls a batch kernel on an empty batch and pins its refusal by the exact exception type and
    /// message. Empty spans already have the length a zero count requires, so the call needs no
    /// rental and leaves nothing but the AVX2 guard to reject it.
    /// </summary>
    /// <param name="operation">The kernel delegate taken from its backend's accessor.</param>
    /// <param name="curve">Curve identity passed to the kernel.</param>
    /// <param name="expectedMessage">The kernel's exact refusal text.</param>
    private static void AssertEmptyBatchRefuses(
        BatchOperation operation,
        CurveParameterSet curve,
        string expectedMessage)
    {
        PlatformNotSupportedException exception = Assert.ThrowsExactly<PlatformNotSupportedException>(
            () => operation(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, EmptyCount, curve));

        Assert.AreEqual(expectedMessage, exception.Message);
    }


    /// <summary>Checks that a refused call left every destination byte at the sentinel, because the AVX2 guard precedes every write.</summary>
    /// <param name="destination">The destination the refused call received.</param>
    private static void AssertDestinationHoldsSentinel(ReadOnlySpan<byte> destination)
    {
        foreach(byte actual in destination)
        {
            Assert.AreEqual(ResultSentinel, actual, "The AVX2 refusal must precede every output write.");
        }
    }
}
