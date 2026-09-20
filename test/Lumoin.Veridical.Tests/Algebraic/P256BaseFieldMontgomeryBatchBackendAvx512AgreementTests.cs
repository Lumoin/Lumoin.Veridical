using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Agreement gate for the AVX-512 lane-parallel Fp256 batch backend
/// <see cref="P256BaseFieldMontgomeryBatchBackendAvx512"/>, the AVX-512 mirror of
/// <see cref="P256BaseFieldMontgomeryBatchBackendAgreementTests"/>. Gated on
/// <see cref="System.Runtime.Intrinsics.X86.Avx512F"/> support, so it reports Inconclusive
/// (not failed) on a host without AVX-512.
/// </summary>
/// <remarks>
/// The bodies mirror the AVX2 gate: the load-bearing belt-and-suspenders test against the
/// scalar single-CIOS <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/> on the
/// same Montgomery residues, the end-to-end test against the BigInteger oracle, the
/// multiply-by-mont(1) identity, and the tail-boundary sweep. <see cref="MainCount"/> is not a
/// multiple of the AVX-512 octet width, so the trailing-element fallback is exercised by every run.
/// Both the live generic <c>m·Modulus32</c> reduction
/// (<see cref="P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery"/>) and the retained
/// P-256-specialized signed-sparse reduction
/// (<see cref="P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce"/>)
/// are driven against the same scalar oracle, so every test pins generic == specialized == scalar
/// <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/>.
/// </remarks>
[TestClass]
internal sealed class P256BaseFieldMontgomeryBatchBackendAvx512AgreementTests
{
    /// <summary>Two hundred property samples retain the existing arithmetic agreement sweep.</summary>
    private const long IterationCount = 200;

    /// <summary>Nineteen lanes are not a multiple of the AVX-512 octet width of eight, so every sample retains complete SIMD groups and a three-element tail, running both the SIMD body and the tail path.</summary>
    private const int MainCount = 19;

    /// <summary>The field identity passed to directly owned kernels.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.None;

    /// <summary>BigInteger reduction into the P-256 base field.</summary>
    private static ScalarReduceDelegate ReferenceReduce { get; } = P256BaseFieldReference.GetReduce();
    /// <summary>Canonical BigInteger multiplication in the P-256 base field.</summary>
    private static ScalarMultiplyDelegate ReferenceMultiply { get; } = P256BaseFieldReference.GetMultiply();
    /// <summary>Scalar residue multiplication used by the existing Montgomery agreement gate.</summary>
    private static ScalarMultiplyDelegate ScalarMultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();


    /// <summary>Keeps this class inconclusive when its instruction set is unavailable.</summary>
    [TestInitialize]
    public void RequireAvx512()
    {
        InstructionSetRequirements.RequireAvx512();
    }


    /// <summary>Checks both batch reductions against scalar multiplication on identical Montgomery residues.</summary>
    [TestMethod]
    public void BatchMontgomeryMultiplyAgreesWithScalarMontgomeryMultiply()
    {
        //The load-bearing gate: residue-in/residue-out, both batch reductions must equal the scalar
        //single-CIOS MultiplyMontgomery on the identical residues — NOT the canonical Multiply.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();

        int size = Scalar.SizeBytes;
        Gen<byte[]> batchGen = Gen.Byte.Array[MainCount * size];
        Gen.Select(batchGen, batchGen).Sample((leftRaw, rightRaw) =>
        {
            Span<byte> left = stackalloc byte[MainCount * size];
            Span<byte> right = stackalloc byte[MainCount * size];
            Span<byte> specialized = stackalloc byte[MainCount * size];
            Span<byte> generic = stackalloc byte[MainCount * size];
            Span<byte> expected = stackalloc byte[MainCount * size];

            for(int i = FirstIndex; i < MainCount; i++)
            {
                int offset = i * size;
                ToMontgomeryResidue(leftRaw.AsSpan(offset, size), left.Slice(offset, size));
                ToMontgomeryResidue(rightRaw.AsSpan(offset, size), right.Slice(offset, size));
            }

            batchSpecialized(left, right, specialized, MainCount, Curve);
            batchGeneric(left, right, generic, MainCount, Curve);

            for(int i = FirstIndex; i < MainCount; i++)
            {
                int offset = i * size;
                ScalarMultiplyMontgomery(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), Curve);
            }

            return specialized.SequenceEqual(expected) && generic.SequenceEqual(expected) && specialized.SequenceEqual(generic);
        }, iter: IterationCount);
    }


    /// <summary>Checks conversion into and out of Montgomery form against canonical BigInteger multiplication.</summary>
    [TestMethod]
    public void BatchMontgomeryMultiplyAgreesWithBigIntegerMultiply()
    {
        //End-to-end: lift canonical operands in, batch-multiply in the Montgomery domain with each reduction,
        //drop out, and compare to the BigInteger oracle a·b mod p.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();

        int size = Scalar.SizeBytes;
        Gen<byte[]> batchGen = Gen.Byte.Array[MainCount * size];
        Gen.Select(batchGen, batchGen).Sample((leftRaw, rightRaw) =>
        {
            Span<byte> leftCanonical = stackalloc byte[MainCount * size];
            Span<byte> rightCanonical = stackalloc byte[MainCount * size];
            Span<byte> leftMont = stackalloc byte[MainCount * size];
            Span<byte> rightMont = stackalloc byte[MainCount * size];
            Span<byte> specializedMont = stackalloc byte[MainCount * size];
            Span<byte> genericMont = stackalloc byte[MainCount * size];

            for(int i = FirstIndex; i < MainCount; i++)
            {
                int offset = i * size;
                ReferenceReduce(leftRaw.AsSpan(offset, size), leftCanonical.Slice(offset, size), Curve);
                ReferenceReduce(rightRaw.AsSpan(offset, size), rightCanonical.Slice(offset, size), Curve);
                P256BaseFieldMontgomeryBackend.ToMontgomery(leftCanonical.Slice(offset, size), leftMont.Slice(offset, size));
                P256BaseFieldMontgomeryBackend.ToMontgomery(rightCanonical.Slice(offset, size), rightMont.Slice(offset, size));
            }

            batchSpecialized(leftMont, rightMont, specializedMont, MainCount, Curve);
            batchGeneric(leftMont, rightMont, genericMont, MainCount, Curve);

            Span<byte> actualSpecialized = stackalloc byte[size];
            Span<byte> actualGeneric = stackalloc byte[size];
            Span<byte> expected = stackalloc byte[size];
            for(int i = FirstIndex; i < MainCount; i++)
            {
                int offset = i * size;
                P256BaseFieldMontgomeryBackend.FromMontgomery(specializedMont.Slice(offset, size), actualSpecialized);
                P256BaseFieldMontgomeryBackend.FromMontgomery(genericMont.Slice(offset, size), actualGeneric);
                ReferenceMultiply(leftCanonical.Slice(offset, size), rightCanonical.Slice(offset, size), expected, Curve);
                if(!actualSpecialized.SequenceEqual(expected) || !actualGeneric.SequenceEqual(expected))
                {

                    return false;
                }
            }

            return true;
        }, iter: IterationCount);
    }


    /// <summary>Checks that multiplying by Montgomery one preserves every residue.</summary>
    [TestMethod]
    public void BatchMontgomeryMultiplyByOneIsIdentity()
    {
        //Multiplying each residue by mont(1) = R mod p leaves it unchanged (the Montgomery-domain identity),
        //and both reductions must hit that identity.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();

        int size = Scalar.SizeBytes;
        Span<byte> canonicalOne = stackalloc byte[Scalar.SizeBytes];
        canonicalOne.Clear();
        canonicalOne[^SingleCount] = SingleCount;
        using IMemoryOwner<byte> montOneOwner = BaseMemoryPool.Shared.Rent(size);
        Memory<byte> montOne = montOneOwner.Memory[..size];
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalOne, montOne.Span);

        Gen<byte[]> batchGen = Gen.Byte.Array[MainCount * size];
        batchGen.Sample(raw =>
        {
            Span<byte> residues = stackalloc byte[MainCount * size];
            Span<byte> ones = stackalloc byte[MainCount * size];
            Span<byte> specialized = stackalloc byte[MainCount * size];
            Span<byte> generic = stackalloc byte[MainCount * size];

            for(int i = FirstIndex; i < MainCount; i++)
            {
                int offset = i * size;
                ToMontgomeryResidue(raw.AsSpan(offset, size), residues.Slice(offset, size));
                montOne.Span.CopyTo(ones.Slice(offset, size));
            }

            batchSpecialized(residues, ones, specialized, MainCount, Curve);
            batchGeneric(residues, ones, generic, MainCount, Curve);

            return specialized.SequenceEqual(residues) && generic.SequenceEqual(residues);
        }, iter: IterationCount);
    }


    /// <summary>Checks both reductions against scalar Montgomery multiplication around SIMD group boundaries.</summary>
    [TestMethod]
    public void BatchMontgomeryMultiplyTailBoundariesAgree()
    {
        //Sweep counts straddling the octet width so the SIMD body, the tail, and their interaction are all
        //covered: each count must agree element-for-element with the scalar single-CIOS multiply, for both
        //reductions.
        ScalarBatchMultiplyDelegate batchGeneric = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery();
        ScalarBatchMultiplyDelegate batchSpecialized = P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce();
        int[] counts =
        [
            SingleCount, TwoLaneCount, TelemetryCount, QuartetCount, AfterQuartetCount,
            BeforeOctetCount, OctetCount, AfterOctetCount, TwoOctetCount, AfterTwoOctetCount
        ];

        int size = Scalar.SizeBytes;
        foreach(int count in counts)
        {
            Gen<byte[]> batchGen = Gen.Byte.Array[count * size];
            Gen.Select(batchGen, batchGen).Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[count * size];
                Span<byte> right = stackalloc byte[count * size];
                Span<byte> specialized = stackalloc byte[count * size];
                Span<byte> generic = stackalloc byte[count * size];
                Span<byte> expected = stackalloc byte[count * size];

                for(int i = FirstIndex; i < count; i++)
                {
                    int offset = i * size;
                    ToMontgomeryResidue(leftRaw.AsSpan(offset, size), left.Slice(offset, size));
                    ToMontgomeryResidue(rightRaw.AsSpan(offset, size), right.Slice(offset, size));
                }

                batchSpecialized(left, right, specialized, count, Curve);
                batchGeneric(left, right, generic, count, Curve);

                for(int i = FirstIndex; i < count; i++)
                {
                    int offset = i * size;
                    ScalarMultiplyMontgomery(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), Curve);
                }

                return specialized.SequenceEqual(expected) && generic.SequenceEqual(expected) && specialized.SequenceEqual(generic);
            }, iter: IterationCount);
        }
    }


    /// <summary>Reduces raw bytes and lifts the canonical value into the P-256 Montgomery domain.</summary>
    /// <param name="raw">The raw scalar bytes.</param>
    /// <param name="residue">Destination for one Montgomery residue.</param>
    private static void ToMontgomeryResidue(ReadOnlySpan<byte> raw, Span<byte> residue)
    {
        Span<byte> canonical = stackalloc byte[Scalar.SizeBytes];
        ReferenceReduce(raw, canonical, Curve);
        P256BaseFieldMontgomeryBackend.ToMontgomery(canonical, residue);
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
    private const string LengthErrorMessage = "Batched Fp256 buffers must each be exactly 1 * 32 bytes for count = 1.";

    /// <summary>Batch multiply montgomery rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void BatchMultiplyMontgomeryRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery().Invoke, oversizedOperand);
    }

    /// <summary>Batch multiply montgomery specialized reduce rejects one extra byte in each operand before writing output.</summary>
    /// <param name="oversizedOperand">The buffer position that exceeds the required scalar width.</param>
    [TestMethod]
    [DataRow(LeftBuffer)]
    [DataRow(RightBuffer)]
    [DataRow(ResultBuffer)]
    public void BatchMultiplyMontgomerySpecializedReduceRejectsOversizedBuffer(int oversizedOperand)
    {
        AssertRejectsOversizedBuffer(P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce().Invoke, oversizedOperand);
    }

    /// <summary>Both directly owned Montgomery batch entry points count three lanes without scalar tail increments.</summary>
    [TestMethod]
    [DoNotParallelize]
    public void BatchMontgomeryOperationsIncrementExactCounts()
    {
        bool wasCountingEnabled = CryptographicOperationCounters.IsCountingEnabled;
        bool wasObservingEnabled = CryptographicOperationCounters.IsObservingEnabled;
        try
        {
            CryptographicOperationCounters.IsCountingEnabled = false;
            CryptographicOperationCounters.IsObservingEnabled = false;
            Span<byte> left = stackalloc byte[TelemetryCount * Scalar.SizeBytes];
            Span<byte> right = stackalloc byte[TelemetryCount * Scalar.SizeBytes];
            Span<byte> result = stackalloc byte[TelemetryCount * Scalar.SizeBytes];
            DeterministicScalarFill.FillCanonical(left, LeftFillSalt, ReferenceReduce, Curve);
            DeterministicScalarFill.FillCanonical(right, RightFillSalt, ReferenceReduce, Curve);
            for(int lane = FirstIndex; lane < TelemetryCount; lane++)
            {
                Span<byte> leftSlot = left.Slice(lane * Scalar.SizeBytes, Scalar.SizeBytes);
                Span<byte> rightSlot = right.Slice(lane * Scalar.SizeBytes, Scalar.SizeBytes);
                P256BaseFieldMontgomeryBackend.ToMontgomery(leftSlot, leftSlot);
                P256BaseFieldMontgomeryBackend.ToMontgomery(rightSlot, rightSlot);
            }

            //Each entry point has its own reset so neither can hide the other's missing increment.
            CryptographicOperationCounters.IsCountingEnabled = true;
            CryptographicOperationCounters.Reset();
            P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery()(left, right, result, TelemetryCount, Curve);
            Assert.AreEqual((long)TelemetryCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiply));
            Assert.HasCount(SingleCount, CryptographicOperationCounters.Snapshot());

            CryptographicOperationCounters.Reset();
            P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomerySpecializedReduce()(left, right, result, TelemetryCount, Curve);
            Assert.AreEqual((long)TelemetryCount, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiply));
            Assert.HasCount(SingleCount, CryptographicOperationCounters.Snapshot());
        }
        finally
        {
            CryptographicOperationCounters.Reset();
            CryptographicOperationCounters.IsCountingEnabled = wasCountingEnabled;
            CryptographicOperationCounters.IsObservingEnabled = wasObservingEnabled;
        }
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
        DeterministicScalarFill.FillCanonical(left.Span[..Scalar.SizeBytes], LeftFillSalt, ReferenceReduce, Curve);
        DeterministicScalarFill.FillCanonical(right.Span[..Scalar.SizeBytes], RightFillSalt, ReferenceReduce, Curve);
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

    /// <summary>Two lanes exercise a short scalar tail in the existing sweep.</summary>
    private const int TwoLaneCount = SingleCount + SingleCount;

    /// <summary>Four lanes are one AVX2 quartet or a partial AVX-512 octet.</summary>
    private const int QuartetCount = 4;

    /// <summary>Five lanes lie immediately above an AVX2 quartet boundary.</summary>
    private const int AfterQuartetCount = QuartetCount + SingleCount;

    /// <summary>Eight lanes are two AVX2 quartets or one AVX-512 octet.</summary>
    private const int OctetCount = QuartetCount + QuartetCount;

    /// <summary>Seven lanes lie immediately below an AVX-512 octet boundary.</summary>
    private const int BeforeOctetCount = OctetCount - SingleCount;

    /// <summary>Nine lanes lie immediately above an AVX-512 octet boundary.</summary>
    private const int AfterOctetCount = OctetCount + SingleCount;

    /// <summary>Sixteen lanes exercise multiple complete SIMD groups.</summary>
    private const int TwoOctetCount = OctetCount + OctetCount;

    /// <summary>Seventeen lanes exercise multiple SIMD groups followed by one scalar.</summary>
    private const int AfterTwoOctetCount = TwoOctetCount + SingleCount;
}
