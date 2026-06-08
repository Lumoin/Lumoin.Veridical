using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Satisfaction-check extension on <see cref="RelaxedR1csInstance"/>.
/// </summary>
/// <remarks>
/// <para>
/// Checks the relaxed identity <c>(A·z) ∘ (B·z) = u · (C·z) + E</c>
/// over <c>z = (u, public_inputs, witness)</c>. The constant slot
/// <c>z[0]</c> equals the relaxation scalar <c>u</c>, not literal 1 —
/// the Nova convention. For a raw instance prepared with <c>u = 1</c>,
/// <c>E = 0</c> the convention coincides with the standard R1CS form
/// <c>z = (1, x, w)</c>; for folded instances <c>z[0] = u_folded ≠ 1</c>
/// and the convention is what makes <c>z_folded = z_1 + r · z_2</c> a
/// clean linear combination.
/// </para>
/// <para>
/// Does <em>not</em> check the Hyrax commitment of <c>E</c> against the
/// explicit error vector in the witness — that's a separate
/// commitment-scheme verification step.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class RelaxedR1csInstanceExtensions
{
    extension(RelaxedR1csInstance instance)
    {
        /// <summary>
        /// Checks the relaxed identity. Returns
        /// <see cref="R1csSatisfaction.Satisfied"/> on success;
        /// otherwise the first failing row as
        /// <see cref="R1csSatisfaction.Violated"/>.
        /// </summary>
        public R1csSatisfaction CheckSatisfiedBy(
            RelaxedR1csWitness witness,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMul,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMul);
            ArgumentNullException.ThrowIfNull(pool);

            if(instance.Curve.Code != witness.Curve.Code)
            {
                throw new ArgumentException(
                    $"Instance ({instance.Curve}) and witness ({witness.Curve}) must share a curve.");
            }

            int scalarSize = R1csMatrix.GetValueByteSize(instance.Curve);
            int n = instance.A.ColumnCount;
            int m = instance.A.RowCount;

            if(witness.ErrorLength != m)
            {
                throw new ArgumentException(
                    $"Witness error length {witness.ErrorLength} must equal constraint count {m}.");
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.RelaxedR1csCheckSatisfaction, instance.Curve);

            using IMemoryOwner<byte> zOwner = pool.Rent(n * scalarSize);
            Span<byte> z = zOwner.Memory.Span[..(n * scalarSize)];
            z.Clear();
            //z[0] = u per the Nova relaxed-R1CS convention; coincides
            //with z[0] = 1 in the prepared-from-raw case (u = 1) and
            //tracks u_folded = u_1 + r · u_2 in the folded case.
            instance.GetUBytes().CopyTo(z[..scalarSize]);
            instance.GetPublicInputsBytes().CopyTo(z[scalarSize..]);
            int witnessOffset = (1 + instance.PublicInputCount) * scalarSize;
            witness.GetWitnessBytes().CopyTo(z[witnessOffset..]);

            using IMemoryOwner<byte> azOwner = pool.Rent(m * scalarSize);
            using IMemoryOwner<byte> bzOwner = pool.Rent(m * scalarSize);
            using IMemoryOwner<byte> czOwner = pool.Rent(m * scalarSize);
            Span<byte> az = azOwner.Memory.Span[..(m * scalarSize)];
            Span<byte> bz = bzOwner.Memory.Span[..(m * scalarSize)];
            Span<byte> cz = czOwner.Memory.Span[..(m * scalarSize)];

            instance.A.MatrixVectorProduct(z, az, scalarAdd, scalarMul, pool);
            instance.B.MatrixVectorProduct(z, bz, scalarAdd, scalarMul, pool);
            instance.C.MatrixVectorProduct(z, cz, scalarAdd, scalarMul, pool);

            ReadOnlySpan<byte> uBytes = instance.GetUBytes();
            ReadOnlySpan<byte> errorBytes = witness.GetErrorBytes();

            using IMemoryOwner<byte> lhsOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> rhsOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
            Span<byte> lhs = lhsOwner.Memory.Span[..scalarSize];
            Span<byte> rhs = rhsOwner.Memory.Span[..scalarSize];
            Span<byte> term = termOwner.Memory.Span[..scalarSize];

            for(int row = 0; row < m; row++)
            {
                ReadOnlySpan<byte> azRow = az.Slice(row * scalarSize, scalarSize);
                ReadOnlySpan<byte> bzRow = bz.Slice(row * scalarSize, scalarSize);
                ReadOnlySpan<byte> czRow = cz.Slice(row * scalarSize, scalarSize);
                ReadOnlySpan<byte> errorRow = errorBytes.Slice(row * scalarSize, scalarSize);

                //lhs = az · bz
                scalarMul(azRow, bzRow, lhs, instance.Curve);

                //rhs = u · cz + E[row]
                scalarMul(uBytes, czRow, term, instance.Curve);
                scalarAdd(term, errorRow, rhs, instance.Curve);

                if(!lhs.SequenceEqual(rhs))
                {
                    return BuildViolatedResult(instance, row, lhs, rhs, pool);
                }
            }


            return new R1csSatisfaction.Satisfied();
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The scalars take ownership of their pool-rented buffers and are returned to the caller through R1csSatisfaction.Violated; the caller's Dispose chains through.")]
    private static R1csSatisfaction.Violated BuildViolatedResult(
        RelaxedR1csInstance instance,
        int row,
        ReadOnlySpan<byte> lhsBytes,
        ReadOnlySpan<byte> rhsBytes,
        SensitiveMemoryPool<byte> pool)
    {
        var lhs = Scalar.FromCanonical(lhsBytes, instance.Curve, pool);
        var rhs = Scalar.FromCanonical(rhsBytes, instance.Curve, pool);

        return new R1csSatisfaction.Violated(
            new R1csConstraintIndex(row),
            lhs,
            rhs,
            CollectInvolvedVariables(instance, row));
    }


    private static List<R1csVariableIndex> CollectInvolvedVariables(RelaxedR1csInstance instance, int row)
    {
        var variables = new SortedSet<int>();
        CollectFromRow(instance.A, row, variables);
        CollectFromRow(instance.B, row, variables);
        CollectFromRow(instance.C, row, variables);

        var result = new List<R1csVariableIndex>(variables.Count);
        foreach(int column in variables)
        {
            result.Add(new R1csVariableIndex(column));
        }


        return result;
    }


    private static void CollectFromRow(R1csMatrix matrix, int row, SortedSet<int> destination)
    {
        for(int i = 0; i < matrix.NonzeroCount; i++)
        {
            int currentRow = BinaryPrimitives.ReadInt32BigEndian(matrix.GetRowIndicesBytes().Slice(i * sizeof(int), sizeof(int)));
            if(currentRow == row)
            {
                int column = BinaryPrimitives.ReadInt32BigEndian(matrix.GetColumnIndicesBytes().Slice(i * sizeof(int), sizeof(int)));
                destination.Add(column);
            }
            else if(currentRow > row)
            {
                return;
            }
        }
    }
}