using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for the relaxed R1CS satisfaction check.
/// </summary>
[TestClass]
internal sealed class RelaxedR1csTests
{
    private static readonly ScalarAddDelegate ScalarAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate ScalarMul = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    [TestMethod]
    public void StandardInstanceAsRelaxedWithUOneEIsZeroIsSatisfied()
    {
        //Build the satisfying multiplication circuit, lift to relaxed
        //form with u = 1 and E = 0. Should pass.
        using RelaxedR1csInstance instance = BuildRelaxedMultiplyInstance(uValue: 1);
        using RelaxedR1csWitness witness = BuildRelaxedMultiplyWitness(x: 3, y: 4, errorValuesAreZero: true, uValue: 1);

        using R1csSatisfaction result = instance.CheckSatisfiedBy(witness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(result);
    }


    [TestMethod]
    public void NonOneURequiresMatchingError()
    {
        //u = 2 with x = 3, y = 4: (Az·Bz) = 12, u·(Cz) = 2·12 = 24.
        //Satisfaction requires E[0] = 12 − 24 = −12 ≡ r − 12 (mod r).
        using RelaxedR1csInstance instance = BuildRelaxedMultiplyInstance(uValue: 2);

        //With error 0, the identity is broken (12 != 24 + 0).
        using RelaxedR1csWitness brokenWitness = BuildRelaxedMultiplyWitness(x: 3, y: 4, errorValuesAreZero: true, uValue: 2);
        using R1csSatisfaction brokenResult = instance.CheckSatisfiedBy(brokenWitness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);
        Assert.IsInstanceOfType<R1csSatisfaction.Violated>(brokenResult);

        //With error = (12 − u·12) = −12 (mod r), satisfaction holds.
        using RelaxedR1csWitness correctWitness = BuildRelaxedMultiplyWitness(x: 3, y: 4, errorValuesAreZero: false, uValue: 2);
        using R1csSatisfaction correctResult = instance.CheckSatisfiedBy(correctWitness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(correctResult);
    }


    [TestMethod]
    public void CheckSatisfiedByUsesUInTheConstantSlot()
    {
        //Regression guard for the z[0] = u Nova convention. Builds a
        //circuit whose only constraint touches column 0 (z[0]·z[1]=z[2]),
        //then constructs a satisfying relaxed instance with u = 2 and
        //the matching error E = u·(z[1] − z[2]). A satisfaction check
        //that hardcodes z[0] = 1 would compute 1·z[1] − u·z[2] − E and
        //reject; the correct z[0] = u check accepts.
        const int uValue = 2;
        const int witness1 = 5;
        const int witness2 = 3;
        const int expectedErrorValue = 4; //E = u·(z[1] − z[2]) = 2·(5 − 3).

        using RelaxedR1csInstance instance = BuildColumnZeroTouchingInstance(uValue);
        using RelaxedR1csWitness witness = BuildColumnZeroTouchingWitness(witness1, witness2, expectedErrorValue);
        using R1csSatisfaction result = instance.CheckSatisfiedBy(witness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(result);

        //Perturbing the error makes the check reject — confirms it
        //actually consults z[0]·z[1] not 1·z[1].
        using RelaxedR1csWitness wrongErrorWitness = BuildColumnZeroTouchingWitness(witness1, witness2, expectedErrorValue + 1);
        using R1csSatisfaction wrongResult = instance.CheckSatisfiedBy(wrongErrorWitness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);
        Assert.IsInstanceOfType<R1csSatisfaction.Violated>(wrongResult);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "RelaxedR1csInstance.Create takes ownership of the cloned matrices and dummy commitment and disposes them through its own Dispose chain.")]
    private static RelaxedR1csInstance BuildColumnZeroTouchingInstance(int uValue)
    {
        //A·z = z[0]; B·z = z[1]; C·z = z[2]. 1 constraint over 4 wires.
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = stackalloc int[] { 0 };

        using IMemoryOwner<byte> oneOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> oneBytes = oneOwner.Memory.Span[..scalarSize];
        oneBytes.Clear();
        oneBytes[scalarSize - 1] = 0x01;

        ReadOnlySpan<int> aColumns = stackalloc int[] { 0 };
        ReadOnlySpan<int> bColumns = stackalloc int[] { 1 };
        ReadOnlySpan<int> cColumns = stackalloc int[] { 2 };

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aColumns, oneBytes, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bColumns, oneBytes, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cColumns, oneBytes, 1, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> uOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> uBytes = uOwner.Memory.Span[..scalarSize];
        WriteCanonical(new BigInteger(uValue), uBytes);

        PolynomialCommitment errorCommitment = BuildDummyCommitment(rowCount: 1, columnCount: 1, variableCount: 0);

        return RelaxedR1csInstance.Create(
            a, b, c, ReadOnlySpan<byte>.Empty, uBytes, errorCommitment, BaseMemoryPool.Shared);
    }


    private static RelaxedR1csWitness BuildColumnZeroTouchingWitness(int z1Value, int z2Value, int errorValue)
    {
        int scalarSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(3 * scalarSize);
        Span<byte> witness = witnessOwner.Memory.Span[..(3 * scalarSize)];
        WriteCanonical(new BigInteger(z1Value), witness.Slice(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(z2Value), witness.Slice(1 * scalarSize, scalarSize));
        WriteCanonical(BigInteger.Zero, witness.Slice(2 * scalarSize, scalarSize));

        using IMemoryOwner<byte> errorOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> error = errorOwner.Memory.Span[..scalarSize];
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        WriteCanonical(((new BigInteger(errorValue) % r) + r) % r, error);

        return RelaxedR1csWitness.FromCanonical(witness, error, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "RelaxedR1csInstance.Create takes ownership of the dummy commitment and disposes it through its own Dispose chain.")]
    private static RelaxedR1csInstance BuildRelaxedMultiplyInstance(int uValue)
    {
        //Reuse R1csTestCircuits matrices.
        using RawR1csInstance standard = R1csTestCircuits.BuildMultiplyCircuit();

        int scalarSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> uOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> uBytes = uOwner.Memory.Span[..scalarSize];
        WriteCanonical(new BigInteger(uValue), uBytes);

        //Dummy error commitment: rowCount=1 (one row in the 1-constraint case).
        PolynomialCommitment errorCommitment = BuildDummyCommitment(rowCount: 1, columnCount: 1, variableCount: 0);

        return RelaxedR1csInstance.Create(
            CloneMatrix(standard.A),
            CloneMatrix(standard.B),
            CloneMatrix(standard.C),
            ReadOnlySpan<byte>.Empty,
            uBytes,
            errorCommitment,
            BaseMemoryPool.Shared);
    }


    private static R1csMatrix CloneMatrix(R1csMatrix source)
    {
        //The RawR1csInstance owns its matrices and will dispose them via the
        //`using` block; the relaxed instance needs its own. Rebuild from
        //the source's triples.
        Span<int> rows = stackalloc int[source.NonzeroCount];
        Span<int> cols = stackalloc int[source.NonzeroCount];
        for(int i = 0; i < source.NonzeroCount; i++)
        {
            (int row, int column) = source.GetTriplePosition(i);
            rows[i] = row;
            cols[i] = column;
        }


        return R1csMatrix.FromSortedTriples(rows, cols, source.GetValuesBytes(), source.RowCount, source.ColumnCount, source.Curve, BaseMemoryPool.Shared);
    }


    private static RelaxedR1csWitness BuildRelaxedMultiplyWitness(int x, int y, bool errorValuesAreZero, int uValue)
    {
        int scalarSize = Scalar.SizeBytes;
        BigInteger fieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(3 * scalarSize);
        Span<byte> witness = witnessOwner.Memory.Span[..(3 * scalarSize)];
        WriteCanonical(new BigInteger(x), witness.Slice(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(y), witness.Slice(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger((long)x * y), witness.Slice(2 * scalarSize, scalarSize));

        using IMemoryOwner<byte> errorOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> error = errorOwner.Memory.Span[..scalarSize];
        if(errorValuesAreZero)
        {
            error.Clear();
        }
        else
        {
            //E[0] = x·y − u·(x·y) (mod r).
            BigInteger expected = new BigInteger((long)x * y) - (new BigInteger(uValue) * new BigInteger((long)x * y));
            WriteCanonical(((expected % fieldOrder) + fieldOrder) % fieldOrder, error);
        }


        return RelaxedR1csWitness.FromCanonical(witness, error, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Builds a scheme-agnostic <see cref="PolynomialCommitment"/> with the
    /// requested row count and an arbitrary in-bounds byte pattern (the same
    /// canonical bytes a Hyrax commitment would carry). The buffer is not a
    /// valid Pedersen commitment to anything; the relaxed satisfaction check
    /// does not read it, so this suffices for batch F's tests. The
    /// <paramref name="columnCount"/> and <paramref name="variableCount"/> are
    /// not carried by the generic leaf type and are accepted only to keep the
    /// call sites self-documenting.
    /// </summary>
    [SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "columnCount/variableCount document the intended Hyrax shape at the call sites; the generic commitment does not carry them.")]
    private static PolynomialCommitment BuildDummyCommitment(int rowCount, int columnCount, int variableCount)
    {
        int g1Size = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
        Span<byte> buffer = stackalloc byte[rowCount * g1Size];
        buffer.Clear();
        //Set the compression flag so the bytes are at least syntactically
        //recognised as a compressed-G1 encoding (not that the check looks).
        for(int i = 0; i < rowCount; i++)
        {
            buffer[i * g1Size] = 0xc0;
        }

        return PolynomialCommitment.FromBytes(
            buffer, CurveParameterSet.Bls12Curve381, CommitmentScheme.Hyrax, BaseMemoryPool.Shared);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}