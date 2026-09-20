using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based agreement tests for the AVX-512 scalar backend
/// specifically. Inconclusive when the host CPU lacks AVX-512F (which
/// is most consumer x64 chips and all ARM hosts), so these tests light
/// up only on Sapphire Rapids / Zen 4+ silicon. Without these the
/// AVX-512 path is exercised only indirectly through the dispatch
/// facade — and only on hosts where it is the top-pick path.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381Avx512ScalarBackendAgreementTests
{
    /// <summary>BigInteger reduction into this curve's scalar field.</summary>
    private static ScalarReduceDelegate ReduceDelegate { get; } =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>Full-width generated material for the existing property samples.</summary>
    private static Gen<byte[]> RawScalarBytesGen { get; } =
        Gen.Byte.Array[Scalar.SizeBytes];

    /// <summary>Two hundred property samples: the arithmetic agreement sweep size used throughout this test suite.</summary>
    private const long IterationCount = 200;


    /// <summary>Context supplied by the test runner.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Keeps this class inconclusive when its instruction set is unavailable.</summary>
    [TestInitialize]
    public void RequireAvx512()
    {
        InstructionSetRequirements.RequireAvx512();
    }


    /// <summary>Checks direct AVX-512 batch multiplication against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx512BatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate avx512BatchMultiply = Bls12Curve381Avx512ScalarBackend.GetBatchMultiply();

        //Nineteen elements exercise two full lane-octets plus a three-element serial
        //tail in one call.
        const int Count = 19;
        int size = Scalar.SizeBytes;

        Gen<byte[]> batchGen = Gen.Byte.Array[Count * size];
        Gen.Select(batchGen, batchGen)
            .Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[Count * size];
                Span<byte> right = stackalloc byte[Count * size];
                Span<byte> batched = stackalloc byte[Count * size];
                Span<byte> expected = stackalloc byte[Count * size];

                for(int i = FirstIndex; i < Count; i++)
                {
                    int offset = i * size;
                    ReduceDelegate(leftRaw.AsSpan(offset, size), left.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                    ReduceDelegate(rightRaw.AsSpan(offset, size), right.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                }

                avx512BatchMultiply(left, right, batched, Count, CurveParameterSet.Bls12Curve381);

                for(int i = FirstIndex; i < Count; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX-512 add against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx512AddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate avx512Add = Bls12Curve381Avx512ScalarBackend.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceSum = a.Add(b, bigIntegerAdd, pool);
                using Scalar avx512Sum = a.Add(b, avx512Add, pool);

                return referenceSum.AsReadOnlySpan().SequenceEqual(avx512Sum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX-512 subtract against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx512SubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate avx512Subtract = Bls12Curve381Avx512ScalarBackend.GetSubtract();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceDiff = a.Subtract(b, bigIntegerSubtract, pool);
                using Scalar avx512Diff = a.Subtract(b, avx512Subtract, pool);

                return referenceDiff.AsReadOnlySpan().SequenceEqual(avx512Diff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX-512 multiply against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx512MultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate avx512Multiply = Bls12Curve381Avx512ScalarBackend.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceProduct = a.Multiply(b, bigIntegerMultiply, pool);
                using Scalar avx512Product = a.Multiply(b, avx512Multiply, pool);

                return referenceProduct.AsReadOnlySpan().SequenceEqual(avx512Product.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX-512 negate against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx512NegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bls12Curve381BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate avx512Negate = Bls12Curve381Avx512ScalarBackend.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceNegation = a.Negate(bigIntegerNegate, pool);
                using Scalar avx512Negation = a.Negate(avx512Negate, pool);

                return referenceNegation.AsReadOnlySpan().SequenceEqual(avx512Negation.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX-512 invert against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx512InvertAgreesWithBigIntegerInvert()
    {
        ScalarInvertDelegate bigIntegerInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate avx512Invert = Bls12Curve381Avx512ScalarBackend.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                if(a.IsZero)
                {

                    return true;
                }

                using Scalar referenceInverse = a.Invert(bigIntegerInvert, pool);
                using Scalar avx512Inverse = a.Invert(avx512Invert, pool);

                return referenceInverse.AsReadOnlySpan().SequenceEqual(avx512Inverse.AsReadOnlySpan());
            }, iter: IterationCount);
    }

    /// <summary>First byte or lane in the zero-based canonical buffers.</summary>
    private const int FirstIndex = 0;

    /// <summary>One scalar isolates exact-length validation from batch iteration.</summary>
    private const int SingleCount = 1;

    /// <summary>Three scalars distinguish batch accounting from a single increment and exercise tails.</summary>
    private const int TelemetryCount = 3;

    /// <summary>One extra byte tests exact equality without causing a later short-span failure.</summary>
    private const int OversizedBytes = Scalar.SizeBytes + SingleCount;

    /// <summary>Left operand position in the malformed-buffer rotations.</summary>
    private const int LeftBuffer = 0;

    /// <summary>Right operand position in the malformed-buffer rotations.</summary>
    private const int RightBuffer = 1;

    /// <summary>Result position in the malformed-buffer rotations.</summary>
    private const int ResultBuffer = 2;

    /// <summary>Nonzero output marker exposes writes before rejection or missing arithmetic stores.</summary>
    private const byte ResultSentinel = 0xA5;

    /// <summary>Fixed left stream makes every full-width canonical lane reproducible.</summary>
    private const int LeftFillSalt = 101;

    /// <summary>A different fixed stream prevents identical left and right lane material.</summary>
    private const int RightFillSalt = 211;

    /// <summary>The current exact-length rejection contract for one canonical operand.</summary>
    private const string LengthErrorMessage = "Batched scalar buffers must each be exactly 1 * 32 bytes for count = 1.";

    /// <summary>Two 64-bit limbs force a borrow through an equal zero limb.</summary>
    private const int TwoLimbBits = 128;

    /// <summary>Five scalar kinds plus three batch kinds are directly owned by this backend.</summary>
    private const int OwnedOperationKindCount = 8;

    /// <summary>The scalar field used by the directly owned kernel and BigInteger oracle.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>Equal limbs without incoming borrow must encode canonical zero in every byte.</summary>
    [TestMethod]
    public void Avx512SubtractEqualLimbsProducesZero()
    {
        AssertSubtractMatchesReference(BigInteger.One, BigInteger.One, BigInteger.Zero);
    }

    /// <summary>A borrow through equal zero limbs yields exactly two low limbs of ones.</summary>
    [TestMethod]
    public void Avx512SubtractBorrowAcrossLimbsAgreesWithBigInteger()
    {
        BigInteger boundary = BigInteger.One << TwoLimbBits;
        AssertSubtractMatchesReference(boundary, BigInteger.One, boundary - BigInteger.One);
    }

    /// <summary>Subtracting one from zero wraps to the scalar-field modulus minus one.</summary>
    [TestMethod]
    public void Avx512SubtractZeroMinusOneAgreesWithBigInteger()
    {
        AssertSubtractMatchesReference(BigInteger.Zero, BigInteger.One, WellKnownCurves.GetScalarFieldOrder(Curve) - BigInteger.One);
    }

    /// <summary>Batch add rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Avx512BatchAddRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(Bls12Curve381Avx512ScalarBackend.GetBatchAdd().Invoke, oversizedOperand);
    }

    /// <summary>Batch subtract rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Avx512BatchSubtractRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(Bls12Curve381Avx512ScalarBackend.GetBatchSubtract().Invoke, oversizedOperand);
    }

    /// <summary>Batch multiply rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Avx512BatchMultiplyRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(Bls12Curve381Avx512ScalarBackend.GetBatchMultiply().Invoke, oversizedOperand);
    }

    /// <summary>Direct scalar calls count once and direct batch calls count their three lanes without double-counting tails.</summary>
    [TestMethod]
    [DoNotParallelize]
    public void Avx512OperationsIncrementExactCounts()
    {
        bool wasCountingEnabled = CryptographicOperationCounters.IsCountingEnabled;
        bool wasObservingEnabled = CryptographicOperationCounters.IsObservingEnabled;
        try
        {
            CryptographicOperationCounters.IsCountingEnabled = false;
            CryptographicOperationCounters.IsObservingEnabled = false;
            Span<byte> one = stackalloc byte[Scalar.SizeBytes];
            Span<byte> result = stackalloc byte[Scalar.SizeBytes];
            Span<byte> leftBatch = stackalloc byte[TelemetryCount * Scalar.SizeBytes];
            Span<byte> rightBatch = stackalloc byte[TelemetryCount * Scalar.SizeBytes];
            Span<byte> batchResult = stackalloc byte[TelemetryCount * Scalar.SizeBytes];
            WriteCanonical(BigInteger.One, one);
            DeterministicScalarFill.FillCanonical(leftBatch, LeftFillSalt, ReduceDelegate, Curve);
            DeterministicScalarFill.FillCanonical(rightBatch, RightFillSalt, ReduceDelegate, Curve);

            //Only directly owned calls contribute inside the measurement window.
            CryptographicOperationCounters.IsCountingEnabled = true;
            CryptographicOperationCounters.Reset();
            Bls12Curve381Avx512ScalarBackend.GetAdd()(one, one, result, Curve);
            Bls12Curve381Avx512ScalarBackend.GetSubtract()(one, one, result, Curve);
            Bls12Curve381Avx512ScalarBackend.GetMultiply()(one, one, result, Curve);
            Bls12Curve381Avx512ScalarBackend.GetNegate()(one, result, Curve);
            Bls12Curve381Avx512ScalarBackend.GetInvert()(one, result, Curve);
            Bls12Curve381Avx512ScalarBackend.GetBatchAdd()(leftBatch, rightBatch, batchResult, TelemetryCount, Curve);
            Bls12Curve381Avx512ScalarBackend.GetBatchSubtract()(leftBatch, rightBatch, batchResult, TelemetryCount, Curve);
            Bls12Curve381Avx512ScalarBackend.GetBatchMultiply()(leftBatch, rightBatch, batchResult, TelemetryCount, Curve);

            Assert.AreEqual((long)SingleCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarAdd));
            Assert.AreEqual((long)SingleCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarSubtract));
            Assert.AreEqual((long)SingleCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarMultiply));
            Assert.AreEqual((long)SingleCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarNegate));
            Assert.AreEqual((long)SingleCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarInvert));
            Assert.AreEqual((long)TelemetryCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchAdd));
            Assert.AreEqual((long)TelemetryCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchSubtract));
            Assert.AreEqual((long)TelemetryCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiply));
            Assert.HasCount(OwnedOperationKindCount, CryptographicOperationCounters.Snapshot());
        }
        finally
        {
            CryptographicOperationCounters.Reset();
            CryptographicOperationCounters.IsCountingEnabled = wasCountingEnabled;
            CryptographicOperationCounters.IsObservingEnabled = wasObservingEnabled;
        }
    }

    /// <summary>Checks every subtraction byte against the scalar-field BigInteger reference and exact edge encoding.</summary>
    /// <param name="leftValue">Canonical minuend.</param>
    /// <param name="rightValue">Canonical subtrahend.</param>
    /// <param name="expectedValue">The independently specified modular difference.</param>
    private static void AssertSubtractMatchesReference(BigInteger leftValue, BigInteger rightValue, BigInteger expectedValue)
    {
        Span<byte> left = stackalloc byte[Scalar.SizeBytes];
        Span<byte> right = stackalloc byte[Scalar.SizeBytes];
        Span<byte> result = stackalloc byte[Scalar.SizeBytes];
        Span<byte> reference = stackalloc byte[Scalar.SizeBytes];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        WriteCanonical(leftValue, left);
        WriteCanonical(rightValue, right);
        WriteCanonical(expectedValue, expected);
        result.Fill(ResultSentinel);

        Bls12Curve381Avx512ScalarBackend.GetSubtract()(left, right, result, Curve);
        Bls12Curve381BigIntegerScalarReference.GetSubtract()(left, right, reference, Curve);

        for(int index = FirstIndex; index < Scalar.SizeBytes; index++)
        {
            Assert.AreEqual(expected[index], reference[index], $"Reference byte {index}.");
            Assert.AreEqual(reference[index], result[index], $"Subtraction byte {index}.");
        }
    }

    /// <summary>Writes a nonnegative value as a zero-padded, big-endian canonical scalar.</summary>
    /// <param name="value">The scalar to encode.</param>
    /// <param name="destination">Exactly one scalar slot.</param>
    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        int byteCount = value.GetByteCount(isUnsigned: true);
        Assert.IsTrue(value.TryWriteBytes(destination[^byteCount..], out _, isUnsigned: true, isBigEndian: true));
    }

    /// <summary>Common span signature for directly owned batch add, subtract, and multiply kernels.</summary>
    /// <param name="left">Concatenated left operands.</param>
    /// <param name="right">Concatenated right operands.</param>
    /// <param name="result">Concatenated destination slots.</param>
    /// <param name="count">Number of canonical slots.</param>
    /// <param name="curve">Field identity passed to the kernel.</param>
    private delegate void BatchOperation(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> result, int count, CurveParameterSet curve);

    /// <summary>Rotates one oversized operand and pins rejection before any destination write.</summary>
    /// <param name="operation">The directly obtained batch kernel.</param>
    /// <param name="oversizedOperand">The operand whose length exceeds the canonical width.</param>
    private static void AssertRejectsOversizedBuffer(BatchOperation operation, int oversizedOperand)
    {
        using IMemoryOwner<byte> leftOwner = BaseMemoryPool.Shared.Rent(OversizedBytes);
        using IMemoryOwner<byte> rightOwner = BaseMemoryPool.Shared.Rent(OversizedBytes);
        using IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(OversizedBytes);
        Memory<byte> left = leftOwner.Memory[..(oversizedOperand == LeftBuffer ? OversizedBytes : Scalar.SizeBytes)];
        Memory<byte> right = rightOwner.Memory[..(oversizedOperand == RightBuffer ? OversizedBytes : Scalar.SizeBytes)];
        Memory<byte> result = resultOwner.Memory[..(oversizedOperand == ResultBuffer ? OversizedBytes : Scalar.SizeBytes)];
        left.Span.Clear();
        right.Span.Clear();
        DeterministicScalarFill.FillCanonical(left.Span[..Scalar.SizeBytes], LeftFillSalt, ReduceDelegate, Curve);
        DeterministicScalarFill.FillCanonical(right.Span[..Scalar.SizeBytes], RightFillSalt, ReduceDelegate, Curve);
        result.Span.Fill(ResultSentinel);

        //Memory owners can be captured; spans are created only inside the single throwing expression.
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => operation(left.Span, right.Span, result.Span, SingleCount, Curve));

        Assert.AreEqual(LengthErrorMessage, exception.Message);
        foreach(byte actual in result.Span)
        {
            Assert.AreEqual(ResultSentinel, actual, "Length rejection must precede every output write.");
        }
    }
}
