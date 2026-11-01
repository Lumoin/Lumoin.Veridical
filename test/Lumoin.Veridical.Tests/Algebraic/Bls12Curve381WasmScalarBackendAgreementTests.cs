using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Seeded differential agreement tests for the WASM PackedSimd scalar backend.
/// Unlike the per-ISA x64/ARM backends, the WASM backend's body is written
/// entirely in cross-platform <see cref="System.Runtime.Intrinsics.Vector128"/>
/// operations, so its internal counter-free cores execute correctly on
/// <em>every</em> host — the core agreement tests below run the exact
/// arithmetic against the BigInteger reference on x64 and ARM development
/// machines and CI, unconditionally. Only the public delegates are gated on
/// <c>PackedSimd.IsSupported</c>; the gate's two sides are each pinned by a
/// dedicated test (the delegate path under WASM, the loud refusal elsewhere).
/// </summary>
[TestClass]
internal sealed class Bls12Curve381WasmScalarBackendAgreementTests
{
    /// <summary>The reference reduce delegate that canonicalizes raw operands.</summary>
    private static ScalarReduceDelegate ReduceDelegate { get; } =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The number of random batches per sweep, run after the boundary pass.</summary>
    private const long IterationCount = 200;

    /// <summary>
    /// The seed of the multiply sweep's random operand stream. Each test draws from its own
    /// SplitMix64 stream so a failure message's seed regenerates that test's inputs alone.
    /// </summary>
    private const ulong MultiplySeed = 0xB12B12B12B12B101UL;

    /// <summary>The seed of the add sweep's random operand stream.</summary>
    private const ulong AddSeed = 0xB12B12B12B12B102UL;

    /// <summary>The seed of the subtract sweep's random operand stream.</summary>
    private const ulong SubtractSeed = 0xB12B12B12B12B103UL;

    /// <summary>The seed of the negate sweep's random operand stream.</summary>
    private const ulong NegateSeed = 0xB12B12B12B12B104UL;

    /// <summary>The seed of the delegate batch add sweep's random operand stream.</summary>
    private const ulong DelegateBatchAddSeed = 0xB12B12B12B12B105UL;

    /// <summary>The seed of the delegate batch subtract sweep's random operand stream.</summary>
    private const ulong DelegateBatchSubtractSeed = 0xB12B12B12B12B106UL;

    /// <summary>The seed of the delegate add sweep's random operand stream.</summary>
    private const ulong DelegateAddSeed = 0xB12B12B12B12B107UL;

    /// <summary>The seed of the delegate subtract sweep's random operand stream.</summary>
    private const ulong DelegateSubtractSeed = 0xB12B12B12B12B108UL;

    /// <summary>The seed of the delegate multiply sweep's random operand stream.</summary>
    private const ulong DelegateMultiplySeed = 0xB12B12B12B12B109UL;

    /// <summary>The seed of the delegate negate sweep's random operand stream.</summary>
    private const ulong DelegateNegateSeed = 0xB12B12B12B12B10AUL;

    /// <summary>The seed of the delegate invert sweep's random operand stream.</summary>
    private const ulong DelegateInvertSeed = 0xB12B12B12B12B10BUL;

    /// <summary>
    /// The number of random operands in the invert sweep. Each inversion is a 254-step
    /// square-and-multiply ladder, so the sweep is shorter than the others to keep an interpreted
    /// WebAssembly run affordable; the boundary pass still covers every edge value.
    /// </summary>
    private const long InvertIterationCount = 40;


    /// <summary>The batch width: two full SIMD pairs plus a serial tail element.</summary>
    private const int BatchCount = 5;


    /// <summary>
    /// Batch multiply core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreBatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();

        WasmScalarAgreementSweep.RunBatch(
            "Bls12Curve381WasmScalarBackend.BatchMultiplyCore",
            MultiplySeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            Bls12Curve381WasmScalarBackend.BatchMultiplyCore,
            bigIntegerMultiply.Invoke);
    }


    /// <summary>
    /// Batch add core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreBatchAddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();

        WasmScalarAgreementSweep.RunBatch(
            "Bls12Curve381WasmScalarBackend.BatchAddCore",
            AddSeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            Bls12Curve381WasmScalarBackend.BatchAddCore,
            bigIntegerAdd.Invoke);
    }


    /// <summary>
    /// Batch subtract core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreBatchSubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();

        WasmScalarAgreementSweep.RunBatch(
            "Bls12Curve381WasmScalarBackend.BatchSubtractCore",
            SubtractSeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            Bls12Curve381WasmScalarBackend.BatchSubtractCore,
            bigIntegerSubtract.Invoke);
    }


    /// <summary>
    /// Negate core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreNegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bls12Curve381BigIntegerScalarReference.GetNegate();

        WasmScalarAgreementSweep.RunUnary(
            "Bls12Curve381WasmScalarBackend.NegateCore",
            NegateSeed,
            IterationCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            Bls12Curve381WasmScalarBackend.NegateCore,
            bigIntegerNegate.Invoke);
    }


    /// <summary>
    /// Off WebAssembly the BLS12-381 delegates throw instead of computing, mirroring the per-ISA backends.
    /// </summary>
    [TestMethod]
    public void WasmDelegatesRefuseLoudlyOffWasm()
    {
        //The other side of the IsSupported gate: off-WASM the delegates must
        //throw rather than silently compute, mirroring the per-ISA backends.
        if(Bls12Curve381WasmScalarBackend.IsSupported)
        {
            Assert.Inconclusive("PackedSimd is supported on this host; the refusal gate is exercised on non-WASM hosts.");
        }

        int size = Scalar.SizeBytes;
        using System.Buffers.IMemoryOwner<byte> operandOwner = BaseMemoryPool.Shared.Rent(size);
        using System.Buffers.IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(size);

        ScalarAddDelegate add = Bls12Curve381WasmScalarBackend.GetAdd();
        Assert.ThrowsExactly<PlatformNotSupportedException>(
            () => add(operandOwner.Memory.Span[..size], operandOwner.Memory.Span[..size], resultOwner.Memory.Span[..size], CurveParameterSet.Bls12Curve381));
    }


    /// <summary>
    /// The BLS12-381 batch multiply delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateBatchMultiplyAgreesUnderPackedSimd()
    {
        //The delegate path under a WASM runtime; Inconclusive everywhere else
        //(the core agreement tests above carry the arithmetic coverage there).
        InstructionSetRequirements.RequirePackedSimd();

        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate wasmBatchMultiply = Bls12Curve381WasmScalarBackend.GetBatchMultiply();

        int size = Scalar.SizeBytes;
        Span<byte> left = stackalloc byte[BatchCount * size];
        Span<byte> right = stackalloc byte[BatchCount * size];
        Span<byte> batched = stackalloc byte[BatchCount * size];
        Span<byte> expected = stackalloc byte[BatchCount * size];

        Span<byte> seed = stackalloc byte[size];
        for(int i = 0; i < BatchCount; i++)
        {
            int offset = i * size;
            seed.Clear();
            seed[^1] = (byte)((i * 17) + 3);
            ReduceDelegate(seed, left.Slice(offset, size), CurveParameterSet.Bls12Curve381);
            seed[^1] = (byte)((i * 29) + 7);
            ReduceDelegate(seed, right.Slice(offset, size), CurveParameterSet.Bls12Curve381);
        }

        wasmBatchMultiply(left, right, batched, BatchCount, CurveParameterSet.Bls12Curve381);

        for(int i = 0; i < BatchCount; i++)
        {
            int offset = i * size;
            bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bls12Curve381);
        }

        Assert.IsTrue(batched.SequenceEqual(expected), "The WASM delegate batch multiply must agree with the BigInteger reference.");
    }


    /// <summary>
    /// The BLS12-381 batch add delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateBatchAddAgreesUnderPackedSimd()
    {
        InstructionSetRequirements.RequirePackedSimd();

        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarBatchAddDelegate wasmBatchAdd = Bls12Curve381WasmScalarBackend.GetBatchAdd();
        CurveParameterSet curve = CurveParameterSet.Bls12Curve381;

        WasmScalarAgreementSweep.RunBatch(
            "Bls12Curve381WasmScalarBackend.GetBatchAdd",
            DelegateBatchAddSeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            curve,
            ReduceDelegate,
            (left, right, result, count) => wasmBatchAdd(left, right, result, count, curve),
            bigIntegerAdd.Invoke);
    }


    /// <summary>
    /// The BLS12-381 batch subtract delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateBatchSubtractAgreesUnderPackedSimd()
    {
        InstructionSetRequirements.RequirePackedSimd();

        ScalarSubtractDelegate bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarBatchSubtractDelegate wasmBatchSubtract = Bls12Curve381WasmScalarBackend.GetBatchSubtract();
        CurveParameterSet curve = CurveParameterSet.Bls12Curve381;

        WasmScalarAgreementSweep.RunBatch(
            "Bls12Curve381WasmScalarBackend.GetBatchSubtract",
            DelegateBatchSubtractSeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            curve,
            ReduceDelegate,
            (left, right, result, count) => wasmBatchSubtract(left, right, result, count, curve),
            bigIntegerSubtract.Invoke);
    }


    /// <summary>
    /// The BLS12-381 single add delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateAddAgreesUnderPackedSimd()
    {
        InstructionSetRequirements.RequirePackedSimd();

        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate wasmAdd = Bls12Curve381WasmScalarBackend.GetAdd();

        WasmScalarAgreementSweep.RunBinary(
            "Bls12Curve381WasmScalarBackend.GetAdd",
            DelegateAddSeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            wasmAdd.Invoke,
            bigIntegerAdd.Invoke);
    }


    /// <summary>
    /// The BLS12-381 single subtract delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateSubtractAgreesUnderPackedSimd()
    {
        InstructionSetRequirements.RequirePackedSimd();

        ScalarSubtractDelegate bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate wasmSubtract = Bls12Curve381WasmScalarBackend.GetSubtract();

        WasmScalarAgreementSweep.RunBinary(
            "Bls12Curve381WasmScalarBackend.GetSubtract",
            DelegateSubtractSeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            wasmSubtract.Invoke,
            bigIntegerSubtract.Invoke);
    }


    /// <summary>
    /// The BLS12-381 single multiply delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateMultiplyAgreesUnderPackedSimd()
    {
        InstructionSetRequirements.RequirePackedSimd();

        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate wasmMultiply = Bls12Curve381WasmScalarBackend.GetMultiply();

        WasmScalarAgreementSweep.RunBinary(
            "Bls12Curve381WasmScalarBackend.GetMultiply",
            DelegateMultiplySeed,
            IterationCount,
            BatchCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            wasmMultiply.Invoke,
            bigIntegerMultiply.Invoke);
    }


    /// <summary>
    /// The BLS12-381 negate delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateNegateAgreesUnderPackedSimd()
    {
        InstructionSetRequirements.RequirePackedSimd();

        ScalarNegateDelegate bigIntegerNegate = Bls12Curve381BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate wasmNegate = Bls12Curve381WasmScalarBackend.GetNegate();

        WasmScalarAgreementSweep.RunUnaryDelegate(
            "Bls12Curve381WasmScalarBackend.GetNegate",
            DelegateNegateSeed,
            IterationCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            wasmNegate.Invoke,
            bigIntegerNegate.Invoke);
    }


    /// <summary>
    /// The BLS12-381 invert delegate agrees with the BigInteger reference on every invertible operand
    /// and refuses zero as the reference does, under PackedSimd; inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateInvertAgreesUnderPackedSimd()
    {
        InstructionSetRequirements.RequirePackedSimd();

        ScalarInvertDelegate bigIntegerInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate wasmInvert = Bls12Curve381WasmScalarBackend.GetInvert();

        //Zero has no inverse and both sides throw there, so the sweep runs through wrappers that map
        //zero to zero; the refusal itself is asserted separately below.
        WasmScalarAgreementSweep.RunUnaryDelegate(
            "Bls12Curve381WasmScalarBackend.GetInvert",
            DelegateInvertSeed,
            InvertIterationCount,
            Bls12Curve381BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bls12Curve381,
            ReduceDelegate,
            WasmScalarAgreementSweep.ZeroToZero(wasmInvert.Invoke),
            WasmScalarAgreementSweep.ZeroToZero(bigIntegerInvert.Invoke));

        int size = Scalar.SizeBytes;
        using System.Buffers.IMemoryOwner<byte> zeroOwner = BaseMemoryPool.Shared.Rent(size);
        using System.Buffers.IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(size);
        Memory<byte> zero = zeroOwner.Memory[..size];
        zero.Span.Clear();
        Memory<byte> result = resultOwner.Memory[..size];

        Assert.ThrowsExactly<InvalidOperationException>(
            () => wasmInvert(zero.Span, result.Span, CurveParameterSet.Bls12Curve381));
    }
}
