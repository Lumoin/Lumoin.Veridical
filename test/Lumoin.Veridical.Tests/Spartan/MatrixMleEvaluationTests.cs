using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Tests for <see cref="MatrixMleEvaluation"/>: the matrix-MLE
/// evaluation and row-slice operations against a hand-built sparse
/// matrix with known coefficients.
/// </summary>
[TestClass]
internal sealed class MatrixMleEvaluationTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly BigInteger FieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;


    [TestMethod]
    public void ConstructorRejectsNonPowerOfTwoRowCount()
    {
        //3 × 4 matrix — 3 rows is not a power of two.
        ReadOnlySpan<int> rows = stackalloc int[] { 0, 1, 2 };
        ReadOnlySpan<int> cols = stackalloc int[] { 0, 0, 0 };

        byte[] values = new byte[3 * Scalar.SizeBytes];
        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(
            rows, cols, values,
            rowCount: 3, columnCount: 4,
            CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => _ = new MatrixMleEvaluation(matrix));
    }


    [TestMethod]
    public void EvaluateAtHypercubeRecoversMatrixEntry()
    {
        //Build a 4×4 matrix (so ℓ_y = ℓ_x = 2). Evaluating at hypercube
        //points (bits(i), bits(j)) must recover A[i, j] exactly.
        //
        //  A:
        //    [ 3 0 5 0 ]
        //    [ 0 7 0 0 ]
        //    [ 0 0 0 11]
        //    [13 0 0 0 ]
        int[] rowIndices = [0, 0, 1, 2, 3];
        int[] columnIndices = [0, 2, 1, 3, 0];
        BigInteger[] values = [new(3), new(5), new(7), new(11), new(13)];

        using R1csMatrix matrix = BuildMatrix(rowIndices, columnIndices, values, 4, 4);
        var evaluation = new MatrixMleEvaluation(matrix);

        Assert.AreEqual(2, evaluation.RowVariableCount);
        Assert.AreEqual(2, evaluation.ColumnVariableCount);

        //Validate the matrix MLE at every hypercube point matches the matrix entry.
        for(int i = 0; i < 4; i++)
        {
            for(int j = 0; j < 4; j++)
            {
                using PointArray ry = BuildHypercubePoint(i, 2);
                using PointArray rx = BuildHypercubePoint(j, 2);
                using Scalar result = evaluation.Evaluate(
                    ry.AsSpan, rx.AsSpan, Add, Subtract, Multiply, BaseMemoryPool.Shared);

                BigInteger resultValue = new(result.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
                BigInteger expected = LookupEntry(rowIndices, columnIndices, values, i, j);
                Assert.AreEqual(expected, resultValue, $"MLE at (bits({i}), bits({j})) should equal A[{i}, {j}].");
            }
        }
    }


    [TestMethod]
    public void EvaluateAgreesWithDirectFormulaAtArbitraryPoint()
    {
        //At a random-ish (r_y, r_x), the MLE equals
        //Σ_(i,j,v) v · eq(r_y, bits(i)) · eq(r_x, bits(j)).
        //Compute both sides and compare.
        int[] rowIndices = [0, 1, 2, 3];
        int[] columnIndices = [1, 2, 0, 3];
        BigInteger[] values = [new(17), new(19), new(23), new(29)];

        using R1csMatrix matrix = BuildMatrix(rowIndices, columnIndices, values, 4, 4);
        var evaluation = new MatrixMleEvaluation(matrix);

        BigInteger[] ryValues = [new(5), new(7)];
        BigInteger[] rxValues = [new(11), new(13)];

        using PointArray ryPoint = BuildPointFromValues(ryValues);
        using PointArray rxPoint = BuildPointFromValues(rxValues);

        using Scalar fromExtension = evaluation.Evaluate(
            ryPoint.AsSpan, rxPoint.AsSpan, Add, Subtract, Multiply, BaseMemoryPool.Shared);
        BigInteger fromExtensionValue = new(fromExtension.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);

        //Direct computation via BigInteger.
        BigInteger expected = BigInteger.Zero;
        for(int t = 0; t < rowIndices.Length; t++)
        {
            BigInteger eqY = EqAtIndex(ryValues, rowIndices[t]);
            BigInteger eqX = EqAtIndex(rxValues, columnIndices[t]);
            BigInteger term = ((values[t] * eqY) % FieldOrder * eqX) % FieldOrder;
            expected = (expected + term) % FieldOrder;
        }

        Assert.AreEqual(expected, fromExtensionValue);
    }


    [TestMethod]
    public void EvaluateRowSliceAgreesWithDirectFormula()
    {
        //EvaluateRowSlice produces a length-cols MLE whose value at
        //bits(j) equals Σ_{(i, j', v) | j' = j} v · eq(r_y, bits(i)).
        //Compute the expected vector via the direct formula and compare
        //byte-for-byte.
        int[] rowIndices = [0, 1, 1, 2, 3];
        int[] columnIndices = [2, 0, 3, 1, 2];
        BigInteger[] values = [new(7), new(11), new(13), new(17), new(19)];

        using R1csMatrix matrix = BuildMatrix(rowIndices, columnIndices, values, 4, 4);
        var evaluation = new MatrixMleEvaluation(matrix);

        BigInteger[] ryValues = [new(31), new(37)];
        using PointArray ryPoint = BuildPointFromValues(ryValues);

        using MultilinearExtension rowSlice = evaluation.EvaluateRowSlice(
            ryPoint.AsSpan, Add, Subtract, Multiply, BaseMemoryPool.Shared);

        Assert.AreEqual(2, rowSlice.VariableCount, "Row slice should be an MLE over the column variables.");
        Assert.AreEqual(4, rowSlice.EvaluationCount);

        //Expected[j] = Σ_{(i, j', v) | j' = j} v · eq(r_y, bits(i)).
        int elementSize = Scalar.SizeBytes;
        for(int j = 0; j < 4; j++)
        {
            BigInteger expected = BigInteger.Zero;
            for(int t = 0; t < rowIndices.Length; t++)
            {
                if(columnIndices[t] != j)
                {
                    continue;
                }

                BigInteger eqY = EqAtIndex(ryValues, rowIndices[t]);
                BigInteger contribution = (values[t] * eqY) % FieldOrder;
                expected = (expected + contribution) % FieldOrder;
            }

            ReadOnlySpan<byte> slot = rowSlice.AsReadOnlySpan().Slice(j * elementSize, elementSize);
            BigInteger actual = new(slot, isUnsigned: true, isBigEndian: true);
            Assert.AreEqual(expected, actual, $"Row slice at column {j} disagreed with the direct formula.");
        }
    }


    [TestMethod]
    public void EvaluateRowSliceAtHypercubeMatchesMatrixRow()
    {
        //At r_y = bits(i_target), the row slice equals the i_target'th row
        //of A as a function over the column hypercube. Evaluating the slice
        //at bits(j) recovers A[i_target, j].
        int[] rowIndices = [0, 1, 1, 2, 3];
        int[] columnIndices = [2, 0, 3, 1, 2];
        BigInteger[] values = [new(7), new(11), new(13), new(17), new(19)];

        using R1csMatrix matrix = BuildMatrix(rowIndices, columnIndices, values, 4, 4);
        var evaluation = new MatrixMleEvaluation(matrix);

        const int Target = 1;
        using PointArray ryPoint = BuildHypercubePoint(Target, 2);
        using MultilinearExtension rowSlice = evaluation.EvaluateRowSlice(
            ryPoint.AsSpan, Add, Subtract, Multiply, BaseMemoryPool.Shared);

        int elementSize = Scalar.SizeBytes;
        for(int j = 0; j < 4; j++)
        {
            BigInteger expected = LookupEntry(rowIndices, columnIndices, values, Target, j);
            ReadOnlySpan<byte> slot = rowSlice.AsReadOnlySpan().Slice(j * elementSize, elementSize);
            BigInteger actual = new(slot, isUnsigned: true, isBigEndian: true);
            Assert.AreEqual(expected, actual, $"Row slice at hypercube column {j} should equal A[{Target}, {j}].");
        }
    }


    [TestMethod]
    public void EvaluateRejectsMismatchedChallengeVectorLength()
    {
        ReadOnlySpan<int> rows = stackalloc int[] { 0 };
        ReadOnlySpan<int> cols = stackalloc int[] { 0 };
        byte[] values = new byte[Scalar.SizeBytes];
        using R1csMatrix matrix = R1csMatrix.FromSortedTriples(
            rows, cols, values, rowCount: 4, columnCount: 4,
            CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        var evaluation = new MatrixMleEvaluation(matrix);

        //Pass a length-1 r_y when ℓ_y = 2. Must throw.
        BigInteger[] tooShortRy = [new(1)];
        BigInteger[] rx = [new(1), new(1)];
        using PointArray ryPoint = BuildPointFromValues(tooShortRy);
        using PointArray rxPoint = BuildPointFromValues(rx);

        Scalar[] ryArray = ToScalarArray(ryPoint);
        Scalar[] rxArray = ToScalarArray(rxPoint);

        try
        {
            //Allocate locals to capture the spans before the lambda so we
            //can dispose deterministically; the assertion is independent of
            //how Evaluate reads the spans.
            Assert.ThrowsExactly<ArgumentException>(() =>
                _ = evaluation.Evaluate(ryArray, rxArray, Add, Subtract, Multiply, BaseMemoryPool.Shared));
        }
        finally
        {
            foreach(Scalar s in ryArray)
            {
                s.Dispose();
            }
            foreach(Scalar s in rxArray)
            {
                s.Dispose();
            }
        }
    }


    private static R1csMatrix BuildMatrix(int[] rowIndices, int[] columnIndices, BigInteger[] values, int rowCount, int columnCount)
    {
        int elementSize = Scalar.SizeBytes;
        byte[] valueBytes = new byte[values.Length * elementSize];
        for(int t = 0; t < values.Length; t++)
        {
            WriteCanonical(values[t], valueBytes.AsSpan(t * elementSize, elementSize));
        }

        return R1csMatrix.FromSortedTriples(
            rowIndices, columnIndices, valueBytes,
            rowCount, columnCount,
            CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static BigInteger LookupEntry(int[] rowIndices, int[] columnIndices, BigInteger[] values, int row, int column)
    {
        for(int t = 0; t < rowIndices.Length; t++)
        {
            if(rowIndices[t] == row && columnIndices[t] == column)
            {
                return values[t];
            }
        }

        return BigInteger.Zero;
    }


    private static BigInteger EqAtIndex(BigInteger[] r, int index)
    {
        BigInteger result = BigInteger.One;
        for(int b = 0; b < r.Length; b++)
        {
            int bit = (index >> b) & 1;
            BigInteger rb = r[b];
            BigInteger factor = bit == 1
                ? rb
                : ((FieldOrder + BigInteger.One - rb) % FieldOrder + FieldOrder) % FieldOrder;
            result = (result * factor) % FieldOrder;
        }

        return result;
    }


    private static PointArray BuildHypercubePoint(int index, int variableCount)
    {
        int elementSize = Scalar.SizeBytes;
        Scalar[] scalars = new Scalar[variableCount];
        for(int b = 0; b < variableCount; b++)
        {
            int bit = (index >> b) & 1;
            byte[] bytes = new byte[elementSize];
            if(bit == 1)
            {
                bytes[^1] = 0x01;
            }
            scalars[b] = Scalar.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        }

        return new PointArray(scalars);
    }


    private static PointArray BuildPointFromValues(BigInteger[] values)
    {
        int elementSize = Scalar.SizeBytes;
        Scalar[] scalars = new Scalar[values.Length];
        for(int b = 0; b < values.Length; b++)
        {
            byte[] bytes = new byte[elementSize];
            WriteCanonical(values[b], bytes);
            scalars[b] = Scalar.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        }

        return new PointArray(scalars);
    }


    private static Scalar[] ToScalarArray(PointArray point) => point.DetachArray();


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
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


    /// <summary>
    /// Owns a vector of scalar handles. Disposes them all together when
    /// the using block exits.
    /// </summary>
    private sealed class PointArray: IDisposable
    {
        private Scalar[]? scalars;

        public PointArray(Scalar[] scalars)
        {
            this.scalars = scalars;
        }

        public ReadOnlySpan<Scalar> AsSpan => scalars;

        public Scalar[] DetachArray()
        {
            Scalar[] result = scalars ?? [];
            scalars = null;
            return result;
        }

        public void Dispose()
        {
            if(scalars is not null)
            {
                foreach(Scalar s in scalars)
                {
                    s?.Dispose();
                }
                scalars = null;
            }
        }
    }
}