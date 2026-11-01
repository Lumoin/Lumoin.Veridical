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
internal sealed class Bn254WasmScalarBackendAgreementTests
{
    /// <summary>The reference reduce delegate that canonicalizes raw operands.</summary>
    private static ScalarReduceDelegate ReduceDelegate { get; } =
        Bn254BigIntegerScalarReference.GetReduce();

    /// <summary>The number of random batches per sweep, run after the boundary pass.</summary>
    private const long IterationCount = 200;

    /// <summary>
    /// The seed of the multiply sweep's random operand stream. Each test draws from its own
    /// SplitMix64 stream so a failure message's seed regenerates that test's inputs alone.
    /// </summary>
    private const ulong MultiplySeed = 0xB254B254B2540001UL;

    /// <summary>The seed of the add sweep's random operand stream.</summary>
    private const ulong AddSeed = 0xB254B254B2540002UL;

    /// <summary>The seed of the subtract sweep's random operand stream.</summary>
    private const ulong SubtractSeed = 0xB254B254B2540003UL;

    /// <summary>The seed of the negate sweep's random operand stream.</summary>
    private const ulong NegateSeed = 0xB254B254B2540004UL;

    /// <summary>The batch width: two full SIMD pairs plus a serial tail element.</summary>
    private const int BatchCount = 5;


    /// <summary>
    /// Batch multiply core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreBatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();

        WasmScalarAgreementSweep.RunBatch(
            "Bn254WasmScalarBackend.BatchMultiplyCore",
            MultiplySeed,
            IterationCount,
            BatchCount,
            Bn254BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bn254,
            ReduceDelegate,
            Bn254WasmScalarBackend.BatchMultiplyCore,
            bigIntegerMultiply.Invoke);
    }


    /// <summary>
    /// Batch add core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreBatchAddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bn254BigIntegerScalarReference.GetAdd();

        WasmScalarAgreementSweep.RunBatch(
            "Bn254WasmScalarBackend.BatchAddCore",
            AddSeed,
            IterationCount,
            BatchCount,
            Bn254BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bn254,
            ReduceDelegate,
            Bn254WasmScalarBackend.BatchAddCore,
            bigIntegerAdd.Invoke);
    }


    /// <summary>
    /// Batch subtract core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreBatchSubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bn254BigIntegerScalarReference.GetSubtract();

        WasmScalarAgreementSweep.RunBatch(
            "Bn254WasmScalarBackend.BatchSubtractCore",
            SubtractSeed,
            IterationCount,
            BatchCount,
            Bn254BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bn254,
            ReduceDelegate,
            Bn254WasmScalarBackend.BatchSubtractCore,
            bigIntegerSubtract.Invoke);
    }


    /// <summary>
    /// Negate core agrees with the BigInteger reference on the boundary pass and the seeded random pass.
    /// </summary>
    [TestMethod]
    public void WasmCoreNegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bn254BigIntegerScalarReference.GetNegate();

        WasmScalarAgreementSweep.RunUnary(
            "Bn254WasmScalarBackend.NegateCore",
            NegateSeed,
            IterationCount,
            Bn254BigIntegerScalarReference.FieldOrder,
            CurveParameterSet.Bn254,
            ReduceDelegate,
            Bn254WasmScalarBackend.NegateCore,
            bigIntegerNegate.Invoke);
    }


    /// <summary>
    /// Off WebAssembly the BN254 delegates throw instead of computing, mirroring the per-ISA backends.
    /// </summary>
    [TestMethod]
    public void WasmDelegatesRefuseLoudlyOffWasm()
    {
        //The other side of the IsSupported gate: off-WASM the delegates must
        //throw rather than silently compute, mirroring the per-ISA backends.
        if(Bn254WasmScalarBackend.IsSupported)
        {
            Assert.Inconclusive("PackedSimd is supported on this host; the refusal gate is exercised on non-WASM hosts.");
        }

        int size = Scalar.SizeBytes;
        using System.Buffers.IMemoryOwner<byte> operandOwner = BaseMemoryPool.Shared.Rent(size);
        using System.Buffers.IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(size);

        ScalarAddDelegate add = Bn254WasmScalarBackend.GetAdd();
        Assert.ThrowsExactly<PlatformNotSupportedException>(
            () => add(operandOwner.Memory.Span[..size], operandOwner.Memory.Span[..size], resultOwner.Memory.Span[..size], CurveParameterSet.Bn254));
    }


    /// <summary>
    /// The BN254 batch multiply delegate agrees with the BigInteger reference under PackedSimd;
    /// inconclusive on hosts without it.
    /// </summary>
    [TestMethod]
    public void WasmDelegateBatchMultiplyAgreesUnderPackedSimd()
    {
        //The delegate path under a WASM runtime; Inconclusive everywhere else
        //(the core agreement tests above carry the arithmetic coverage there).
        InstructionSetRequirements.RequirePackedSimd();

        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate wasmBatchMultiply = Bn254WasmScalarBackend.GetBatchMultiply();

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
            ReduceDelegate(seed, left.Slice(offset, size), CurveParameterSet.Bn254);
            seed[^1] = (byte)((i * 29) + 7);
            ReduceDelegate(seed, right.Slice(offset, size), CurveParameterSet.Bn254);
        }

        wasmBatchMultiply(left, right, batched, BatchCount, CurveParameterSet.Bn254);

        for(int i = 0; i < BatchCount; i++)
        {
            int offset = i * size;
            bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bn254);
        }

        Assert.IsTrue(batched.SequenceEqual(expected), "The WASM delegate batch multiply must agree with the BigInteger reference.");
    }
}
