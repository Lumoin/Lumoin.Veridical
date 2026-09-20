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
/// Property-based agreement tests for the AVX2 scalar backend
/// specifically — not the dispatch facade. On hosts that also have
/// AVX-512, the facade picks AVX-512 and the AVX2 path goes untested
/// there unless these tests exist. <see cref="TestInitializeAttribute"/> gates
/// the whole class on <see cref="System.Runtime.Intrinsics.X86.Avx2.IsSupported"/>.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381Avx2ScalarBackendAgreementTests
{
    /// <summary>BigInteger reduction into this curve's scalar field.</summary>
    private static ScalarReduceDelegate ReduceDelegate { get; } =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>Full-width generated material for the existing property samples.</summary>
    private static Gen<byte[]> RawScalarBytesGen { get; } =
        Gen.Byte.Array[Scalar.SizeBytes];

    /// <summary>Two hundred property samples retain the existing arithmetic agreement sweep.</summary>
    private const long IterationCount = 200;


    /// <summary>Context supplied by the test runner.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Keeps this class inconclusive when its instruction set is unavailable.</summary>
    [TestInitialize]
    public void RequireAvx2()
    {
        InstructionSetRequirements.RequireAvx2();
    }


    /// <summary>Checks direct AVX2 add against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx2AddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate avx2Add = Bls12Curve381Avx2ScalarBackend.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceSum = a.Add(b, bigIntegerAdd, pool);
                using Scalar avx2Sum = a.Add(b, avx2Add, pool);

                return referenceSum.AsReadOnlySpan().SequenceEqual(avx2Sum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX2 subtract against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx2SubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate avx2Subtract = Bls12Curve381Avx2ScalarBackend.GetSubtract();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceDiff = a.Subtract(b, bigIntegerSubtract, pool);
                using Scalar avx2Diff = a.Subtract(b, avx2Subtract, pool);

                return referenceDiff.AsReadOnlySpan().SequenceEqual(avx2Diff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX2 multiply against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx2MultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate avx2Multiply = Bls12Curve381Avx2ScalarBackend.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceProduct = a.Multiply(b, bigIntegerMultiply, pool);
                using Scalar avx2Product = a.Multiply(b, avx2Multiply, pool);

                return referenceProduct.AsReadOnlySpan().SequenceEqual(avx2Product.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX2 batch multiplication against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx2BatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate avx2BatchMultiply = Bls12Curve381Avx2ScalarBackend.GetBatchMultiply();

        //Eleven elements exercise two full lane-quartets plus a three-element serial
        //tail in one call.
        const int Count = 11;
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

                avx2BatchMultiply(left, right, batched, Count, CurveParameterSet.Bls12Curve381);

                for(int i = FirstIndex; i < Count; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX2 negate against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx2NegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bls12Curve381BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate avx2Negate = Bls12Curve381Avx2ScalarBackend.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceNegation = a.Negate(bigIntegerNegate, pool);
                using Scalar avx2Negation = a.Negate(avx2Negate, pool);

                return referenceNegation.AsReadOnlySpan().SequenceEqual(avx2Negation.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    /// <summary>Checks direct AVX2 invert against the scalar-field BigInteger reference.</summary>
    [TestMethod]
    public void Avx2InvertAgreesWithBigIntegerInvert()
    {
        ScalarInvertDelegate bigIntegerInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate avx2Invert = Bls12Curve381Avx2ScalarBackend.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                //Zero is not invertible; both backends throw on it. A random reduced
                //value lands on zero with negligible probability, but skip it so the
                //sweep tests only the inversion identity, not the throw contract.
                if(a.IsZero)
                {

                    return true;
                }

                using Scalar referenceInverse = a.Invert(bigIntegerInvert, pool);
                using Scalar avx2Inverse = a.Invert(avx2Invert, pool);

                return referenceInverse.AsReadOnlySpan().SequenceEqual(avx2Inverse.AsReadOnlySpan());
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
    public void Avx2SubtractEqualLimbsProducesZero()
    {
        AssertSubtractMatchesReference(BigInteger.One, BigInteger.One, BigInteger.Zero);
    }

    /// <summary>A borrow through equal zero limbs yields exactly two low limbs of ones.</summary>
    [TestMethod]
    public void Avx2SubtractBorrowAcrossLimbsAgreesWithBigInteger()
    {
        BigInteger boundary = BigInteger.One << TwoLimbBits;
        AssertSubtractMatchesReference(boundary, BigInteger.One, boundary - BigInteger.One);
    }

    /// <summary>Subtracting one from zero wraps to the scalar-field modulus minus one.</summary>
    [TestMethod]
    public void Avx2SubtractZeroMinusOneAgreesWithBigInteger()
    {
        AssertSubtractMatchesReference(BigInteger.Zero, BigInteger.One, WellKnownCurves.GetScalarFieldOrder(Curve) - BigInteger.One);
    }

    /// <summary>Batch add rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Avx2BatchAddRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(Bls12Curve381Avx2ScalarBackend.GetBatchAdd().Invoke, oversizedOperand);
    }

    /// <summary>Batch subtract rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Avx2BatchSubtractRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(Bls12Curve381Avx2ScalarBackend.GetBatchSubtract().Invoke, oversizedOperand);
    }

    /// <summary>Batch multiply rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void Avx2BatchMultiplyRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(Bls12Curve381Avx2ScalarBackend.GetBatchMultiply().Invoke, oversizedOperand);
    }

    /// <summary>Direct scalar calls count once and direct batch calls count their three lanes without double-counting tails.</summary>
    [TestMethod]
    [DoNotParallelize]
    public void Avx2OperationsIncrementExactCounts()
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
            Bls12Curve381Avx2ScalarBackend.GetAdd()(one, one, result, Curve);
            Bls12Curve381Avx2ScalarBackend.GetSubtract()(one, one, result, Curve);
            Bls12Curve381Avx2ScalarBackend.GetMultiply()(one, one, result, Curve);
            Bls12Curve381Avx2ScalarBackend.GetNegate()(one, result, Curve);
            Bls12Curve381Avx2ScalarBackend.GetInvert()(one, result, Curve);
            Bls12Curve381Avx2ScalarBackend.GetBatchAdd()(leftBatch, rightBatch, batchResult, TelemetryCount, Curve);
            Bls12Curve381Avx2ScalarBackend.GetBatchSubtract()(leftBatch, rightBatch, batchResult, TelemetryCount, Curve);
            Bls12Curve381Avx2ScalarBackend.GetBatchMultiply()(leftBatch, rightBatch, batchResult, TelemetryCount, Curve);

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

        Bls12Curve381Avx2ScalarBackend.GetSubtract()(left, right, result, Curve);
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

    /// <summary>An empty batch has no slots and must bypass memory rentals.</summary>
    private const int EmptyCount = 0;

    /// <summary>A quartet holds four independent scalars in AVX2's 64-bit lanes.</summary>
    private const int QuartetCount = 4;

    /// <summary>Three lanes exercise the longest scalar-only tail.</summary>
    private const int BeforeQuartetCount = QuartetCount - SingleCount;

    /// <summary>Five lanes exercise a quartet followed by one scalar.</summary>
    private const int AfterQuartetCount = QuartetCount + SingleCount;

    /// <summary>Eight lanes exercise the second full quartet.</summary>
    private const int TwoQuartetCount = QuartetCount + QuartetCount;

    /// <summary>Nine lanes combine two quartets and a one-scalar tail.</summary>
    private const int AfterTwoQuartetCount = TwoQuartetCount + SingleCount;

    /// <summary>Eleven lanes combine two quartets and the longest scalar tail.</summary>
    private const int TwoQuartetsWithTailCount = TwoQuartetCount + BeforeQuartetCount;

    /// <summary>A 64-bit carry or borrow crosses the first limb boundary.</summary>
    private const int OneLimbBits = 64;

    /// <summary>Three limbs force a borrow chain into the highest scalar limb.</summary>
    private const int ThreeLimbBits = TwoLimbBits + OneLimbBits;

    /// <summary>Six distinct boundary pairs rotate through SIMD lanes and scalar tails.</summary>
    private const int BoundaryPairCount = 6;

    /// <summary>Direct batch addition agrees byte-for-byte across empty, quartet, and tail boundaries.</summary>
    /// <param name="count">The number of distinct canonical operand pairs.</param>
    [TestMethod]
    [DataRow(EmptyCount)]
    [DataRow(SingleCount)]
    [DataRow(BeforeQuartetCount)]
    [DataRow(QuartetCount)]
    [DataRow(AfterQuartetCount)]
    [DataRow(TwoQuartetCount)]
    [DataRow(AfterTwoQuartetCount)]
    [DataRow(TwoQuartetsWithTailCount)]
    public void Avx2BatchAddBoundaryCountsAgreeWithBigInteger(int count)
    {
        AssertBatchMatchesBigInteger(Bls12Curve381Avx2ScalarBackend.GetBatchAdd().Invoke, count, subtract: false);
    }

    /// <summary>Direct batch subtraction agrees byte-for-byte across empty, quartet, and tail boundaries.</summary>
    /// <param name="count">The number of distinct canonical operand pairs.</param>
    [TestMethod]
    [DataRow(EmptyCount)]
    [DataRow(SingleCount)]
    [DataRow(BeforeQuartetCount)]
    [DataRow(QuartetCount)]
    [DataRow(AfterQuartetCount)]
    [DataRow(TwoQuartetCount)]
    [DataRow(AfterTwoQuartetCount)]
    [DataRow(TwoQuartetsWithTailCount)]
    public void Avx2BatchSubtractBoundaryCountsAgreeWithBigInteger(int count)
    {
        AssertBatchMatchesBigInteger(Bls12Curve381Avx2ScalarBackend.GetBatchSubtract().Invoke, count, subtract: true);
    }

    /// <summary>Combines distinct full-width deterministic lanes with rotating carry, borrow, and reduction pairs.</summary>
    /// <param name="operation">The directly obtained AVX2 batch operation.</param>
    /// <param name="count">The number of canonical operand pairs.</param>
    /// <param name="subtract">Whether the oracle computes modular subtraction.</param>
    private static void AssertBatchMatchesBigInteger(BatchOperation operation, int count, bool subtract)
    {
        if(count == EmptyCount)
        {
            //The kernel validates empty spans and executes neither quartets nor tail iterations.
            operation(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, count, Curve);

            return;
        }

        int byteCount = count * Scalar.SizeBytes;
        using IMemoryOwner<byte> leftOwner = BaseMemoryPool.Shared.Rent(byteCount);
        using IMemoryOwner<byte> rightOwner = BaseMemoryPool.Shared.Rent(byteCount);
        using IMemoryOwner<byte> resultOwner = BaseMemoryPool.Shared.Rent(byteCount);
        Span<byte> left = leftOwner.Memory.Span[..byteCount];
        Span<byte> right = rightOwner.Memory.Span[..byteCount];
        Span<byte> result = resultOwner.Memory.Span[..byteCount];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        BigInteger order = WellKnownCurves.GetScalarFieldOrder(Curve);
        (BigInteger Left, BigInteger Right)[] boundaries = GetBoundaryPairs(subtract);
        Assert.HasCount(BoundaryPairCount, boundaries);

        for(int rotation = FirstIndex; rotation < BoundaryPairCount; rotation++)
        {
            DeterministicScalarFill.FillCanonical(left, LeftFillSalt, ReduceDelegate, Curve);
            DeterministicScalarFill.FillCanonical(right, RightFillSalt, ReduceDelegate, Curve);
            for(int lane = FirstIndex; lane < Math.Min(count, BoundaryPairCount); lane++)
            {
                (BigInteger leftValue, BigInteger rightValue) = boundaries[(lane + rotation) % BoundaryPairCount];
                WriteCanonical(leftValue, left.Slice(lane * Scalar.SizeBytes, Scalar.SizeBytes));
                WriteCanonical(rightValue, right.Slice(lane * Scalar.SizeBytes, Scalar.SizeBytes));
            }

            //Every count sees every edge, including scalar-only calls and lanes inside a complete quartet.
            result.Fill(ResultSentinel);
            operation(left, right, result, count, Curve);
            for(int lane = FirstIndex; lane < count; lane++)
            {
                int offset = lane * Scalar.SizeBytes;
                BigInteger leftValue = new(left.Slice(offset, Scalar.SizeBytes), isUnsigned: true, isBigEndian: true);
                BigInteger rightValue = new(right.Slice(offset, Scalar.SizeBytes), isUnsigned: true, isBigEndian: true);
                BigInteger value = subtract ? leftValue - rightValue : leftValue + rightValue;
                WriteCanonical((value % order + order) % order, expected);
                for(int index = FirstIndex; index < Scalar.SizeBytes; index++)
                {
                    Assert.AreEqual(expected[index], result[offset + index],
                        $"Count {count}, rotation {rotation}, lane {lane}, byte {index}.");
                }
            }
        }
    }

    /// <summary>Supplies distinct boundary pairs using this curve's scalar modulus.</summary>
    /// <param name="subtract">Whether to supply borrow boundaries or carry and reduction boundaries.</param>
    /// <returns>The six canonical operand pairs.</returns>
    private static (BigInteger Left, BigInteger Right)[] GetBoundaryPairs(bool subtract)
    {
        BigInteger order = WellKnownCurves.GetScalarFieldOrder(Curve);
        BigInteger limbBoundary = BigInteger.One << OneLimbBits;
        BigInteger twoLimbBoundary = BigInteger.One << TwoLimbBits;
        if(subtract)
        {
            //Equal limbs, two- and three-limb borrows, and modular wrap all have distinct minuends.

            return
            [
                (BigInteger.One, BigInteger.One),
                (twoLimbBoundary, BigInteger.One),
                (BigInteger.Zero, BigInteger.One),
                (limbBoundary, BigInteger.One),
                (BigInteger.One << ThreeLimbBits, BigInteger.One),
                (order - BigInteger.One, order - BigInteger.One - BigInteger.One)
            ];
        }

        //The third pair carries out of two limbs; the fourth sums to exactly 2^128 - 1.

        return
        [
            (order - BigInteger.One, BigInteger.One),
            (limbBoundary - BigInteger.One, BigInteger.One),
            (twoLimbBoundary - BigInteger.One, BigInteger.One),
            (limbBoundary, twoLimbBoundary - limbBoundary - BigInteger.One),
            (BigInteger.Zero, BigInteger.Zero),
            (order - BigInteger.One - BigInteger.One, order - BigInteger.One)
        ];
    }
}
