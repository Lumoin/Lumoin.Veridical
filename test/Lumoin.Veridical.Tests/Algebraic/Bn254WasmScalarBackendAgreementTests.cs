using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based agreement tests for the WASM PackedSimd scalar backend.
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
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bn254BigIntegerScalarReference.GetReduce();

    private const long IterationCount = 200;

    //Five elements exercise two full SIMD pairs plus a one-element serial
    //tail in one call on the 2-wide backend.
    private const int BatchCount = 5;


    [TestMethod]
    public void WasmCoreBatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();

        int size = Scalar.SizeBytes;
        Gen<byte[]> batchGen = Gen.Byte.Array[BatchCount * size];
        Gen.Select(batchGen, batchGen)
            .Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[BatchCount * size];
                Span<byte> right = stackalloc byte[BatchCount * size];
                Span<byte> batched = stackalloc byte[BatchCount * size];
                Span<byte> expected = stackalloc byte[BatchCount * size];

                for(int i = 0; i < BatchCount; i++)
                {
                    int offset = i * size;
                    ReduceDelegate(leftRaw.AsSpan(offset, size), left.Slice(offset, size), CurveParameterSet.Bn254);
                    ReduceDelegate(rightRaw.AsSpan(offset, size), right.Slice(offset, size), CurveParameterSet.Bn254);
                }

                Bn254WasmScalarBackend.BatchMultiplyCore(left, right, batched, BatchCount);

                for(int i = 0; i < BatchCount; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bn254);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void WasmCoreBatchAddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bn254BigIntegerScalarReference.GetAdd();

        int size = Scalar.SizeBytes;
        Gen<byte[]> batchGen = Gen.Byte.Array[BatchCount * size];
        Gen.Select(batchGen, batchGen)
            .Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[BatchCount * size];
                Span<byte> right = stackalloc byte[BatchCount * size];
                Span<byte> batched = stackalloc byte[BatchCount * size];
                Span<byte> expected = stackalloc byte[BatchCount * size];

                for(int i = 0; i < BatchCount; i++)
                {
                    int offset = i * size;
                    ReduceDelegate(leftRaw.AsSpan(offset, size), left.Slice(offset, size), CurveParameterSet.Bn254);
                    ReduceDelegate(rightRaw.AsSpan(offset, size), right.Slice(offset, size), CurveParameterSet.Bn254);
                }

                Bn254WasmScalarBackend.BatchAddCore(left, right, batched, BatchCount);

                for(int i = 0; i < BatchCount; i++)
                {
                    int offset = i * size;
                    bigIntegerAdd(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bn254);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void WasmCoreBatchSubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bn254BigIntegerScalarReference.GetSubtract();

        int size = Scalar.SizeBytes;
        Gen<byte[]> batchGen = Gen.Byte.Array[BatchCount * size];
        Gen.Select(batchGen, batchGen)
            .Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[BatchCount * size];
                Span<byte> right = stackalloc byte[BatchCount * size];
                Span<byte> batched = stackalloc byte[BatchCount * size];
                Span<byte> expected = stackalloc byte[BatchCount * size];

                for(int i = 0; i < BatchCount; i++)
                {
                    int offset = i * size;
                    ReduceDelegate(leftRaw.AsSpan(offset, size), left.Slice(offset, size), CurveParameterSet.Bn254);
                    ReduceDelegate(rightRaw.AsSpan(offset, size), right.Slice(offset, size), CurveParameterSet.Bn254);
                }

                Bn254WasmScalarBackend.BatchSubtractCore(left, right, batched, BatchCount);

                for(int i = 0; i < BatchCount; i++)
                {
                    int offset = i * size;
                    bigIntegerSubtract(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bn254);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void WasmCoreNegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bn254BigIntegerScalarReference.GetNegate();

        int size = Scalar.SizeBytes;
        Gen.Byte.Array[size]
            .Sample(aRaw =>
            {
                Span<byte> a = stackalloc byte[size];
                Span<byte> actual = stackalloc byte[size];
                Span<byte> expected = stackalloc byte[size];

                ReduceDelegate(aRaw, a, CurveParameterSet.Bn254);

                Bn254WasmScalarBackend.NegateCore(a, actual);
                bigIntegerNegate(a, expected, CurveParameterSet.Bn254);

                return actual.SequenceEqual(expected);
            }, iter: IterationCount);
    }


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
