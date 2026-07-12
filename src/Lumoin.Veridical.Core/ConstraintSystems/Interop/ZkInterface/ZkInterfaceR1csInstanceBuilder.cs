using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// An <see cref="IZkInterfaceMessageSink"/> that folds a decoded
/// ZkInterface stream into a <see cref="RawR1csInstance"/>. It reconciles
/// the header's <c>field_maximum</c> against the curve, accumulates the
/// constraint terms into the three R1CS matrices, and builds the instance
/// when <see cref="Build"/> is called.
/// </summary>
/// <remarks>
/// <para>
/// Variable IDs index columns directly: column = variable ID, with ID 0
/// the constant one (column 0). The column count is the variable space the
/// header declares (<c>free_variable_id</c>), widened if a constraint ever
/// references a higher ID. This keeps the instance's columns aligned with a
/// witness read by the same ID convention without a separate remap table.
/// </para>
/// <para>
/// Public-input convention (as the Circom reader): every variable but the
/// constant one is treated as private witness from Veridical's perspective
/// (<see cref="RawR1csInstance.PublicInputCount"/> = 0); the genuine
/// instance/witness split is the open W.3 decision.
/// </para>
/// </remarks>
internal sealed class ZkInterfaceR1csInstanceBuilder: IZkInterfaceMessageSink
{
    private readonly CurveParameterSet curve;
    private readonly BaseMemoryPool pool;
    private readonly int scalarSizeBytes;

    private readonly TripleAccumulator aTriples;
    private readonly TripleAccumulator bTriples;
    private readonly TripleAccumulator cTriples;

    private bool fieldSeen;
    private bool freeVariableIdSeen;
    private ulong freeVariableId;
    private long maxVariableId = -1;
    private int currentRow = -1;
    private int constraintCount;


    public ZkInterfaceR1csInstanceBuilder(CurveParameterSet curve, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        this.curve = curve;
        this.pool = pool;
        scalarSizeBytes = R1csMatrix.GetValueByteSize(curve);
        aTriples = new TripleAccumulator(scalarSizeBytes);
        bTriples = new TripleAccumulator(scalarSizeBytes);
        cTriples = new TripleAccumulator(scalarSizeBytes);
    }


    public void OnFieldMaximum(ReadOnlySpan<byte> fieldMaximumLittleEndian)
    {
        if(fieldSeen)
        {
            throw new ArgumentException("ZkInterface stream declares more than one CircuitHeader field_maximum.");
        }

        fieldSeen = true;
        ZkInterfaceFieldReconciler.ThrowIfFieldDoesNotMatch(fieldMaximumLittleEndian, curve);
    }


    public void OnFreeVariableId(ulong freeVariableId)
    {
        //A complete circuit carries a single header; tolerate repeats by
        //keeping the widest declared variable space.
        this.freeVariableId = Math.Max(this.freeVariableId, freeVariableId);
        freeVariableIdSeen = true;
    }


    public void OnInstanceVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
    {
        //Values are ignored under the PublicInputCount = 0 convention; the ID
        //still participates in sizing the column space.
        TrackVariableId(variableId);
    }


    public void BeginConstraint()
    {
        currentRow++;
        constraintCount++;
    }


    public void OnConstraintTerm(ZkInterfaceConstraintMatrix matrix, ulong variableId, ReadOnlySpan<byte> coefficientLittleEndian)
    {
        if(currentRow < 0)
        {
            throw new InvalidOperationException("ZkInterface constraint term reported outside a BeginConstraint/EndConstraint pair.");
        }

        int column = TrackVariableId(variableId);
        Accumulator(matrix).Add(currentRow, column, coefficientLittleEndian);
    }


    /// <summary>Assembles the accumulated constraints into an instance.</summary>
    public RawR1csInstance Build()
    {
        if(!fieldSeen)
        {
            //An undeclared field cannot be validated against the curve; reject
            //rather than assume it matches.
            throw ZkInterfaceFieldReconciler.AbsentFieldException(curve);
        }

        if(constraintCount == 0)
        {
            throw new ArgumentException("ZkInterface stream declares no constraints; a ConstraintSystem message is required.");
        }

        int columnCount = ResolveColumnCount();

        R1csMatrix a = aTriples.Build(constraintCount, columnCount, curve, pool);
        R1csMatrix b;
        R1csMatrix c;

        try
        {
            b = bTriples.Build(constraintCount, columnCount, curve, pool);
        }
        catch
        {
            a.Dispose();
            throw;
        }

        try
        {
            c = cTriples.Build(constraintCount, columnCount, curve, pool);
        }
        catch
        {
            a.Dispose();
            b.Dispose();
            throw;
        }

        try
        {
            //PublicInputCount = 0; the whole z[1..] is private witness from
            //Veridical's perspective (see remarks).
            return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, pool);
        }
        catch
        {
            a.Dispose();
            b.Dispose();
            c.Dispose();
            throw;
        }
    }


    private int ResolveColumnCount()
    {
        int fromFreeVariableId = 0;
        if(freeVariableIdSeen)
        {
            if(freeVariableId > int.MaxValue)
            {
                throw new ArgumentException($"ZkInterface free_variable_id {freeVariableId} exceeds the addressable column range.");
            }

            fromFreeVariableId = (int)freeVariableId;
        }

        int fromReferencedIds = maxVariableId < 0 ? 0 : checked((int)(maxVariableId + 1));
        int columnCount = Math.Max(fromFreeVariableId, fromReferencedIds);

        if(columnCount < 1)
        {
            throw new ArgumentException("ZkInterface stream declares no variables.");
        }

        return columnCount;
    }


    private int TrackVariableId(ulong variableId)
    {
        //The resolved column count is maxVariableId + 1 and must fit in Int32; a variable id at
        //Int32.MaxValue would need Int32.MaxValue + 1 columns, overflowing the checked cast in
        //ResolveColumnCount. Reject it here as an out-of-range id rather than as an OverflowException.
        if(variableId >= int.MaxValue)
        {
            throw new ArgumentException($"ZkInterface variable id {variableId} exceeds the addressable column range.");
        }

        if((long)variableId > maxVariableId)
        {
            maxVariableId = (long)variableId;
        }

        return (int)variableId;
    }


    private TripleAccumulator Accumulator(ZkInterfaceConstraintMatrix matrix) => matrix switch
    {
        ZkInterfaceConstraintMatrix.A => aTriples,
        ZkInterfaceConstraintMatrix.B => bTriples,
        ZkInterfaceConstraintMatrix.C => cTriples,
        _ => throw new ArgumentOutOfRangeException(nameof(matrix), matrix, "Unknown R1CS matrix selector."),
    };


    /// <summary>
    /// Accumulates one matrix's (row, column, coefficient) triples.
    /// Coefficients arrive little-endian and may be shorter than the scalar
    /// field (truncated → zero-pad the high bytes) or longer (the surplus
    /// high bytes must be zero); each is stored reversed into canonical
    /// big-endian.
    /// </summary>
    private sealed class TripleAccumulator
    {
        private readonly int scalarSizeBytes;
        private readonly List<int> rows = new();
        private readonly List<int> columns = new();
        private readonly List<byte> valueBytes = new();


        public TripleAccumulator(int scalarSizeBytes)
        {
            this.scalarSizeBytes = scalarSizeBytes;
        }


        public void Add(int row, int column, ReadOnlySpan<byte> coefficientLittleEndian)
        {
            rows.Add(row);
            columns.Add(column);

            Span<byte> bigEndian = stackalloc byte[scalarSizeBytes];
            ZkInterfaceScalar.WriteCanonicalBigEndian(coefficientLittleEndian, bigEndian);
            for(int j = 0; j < scalarSizeBytes; j++)
            {
                valueBytes.Add(bigEndian[j]);
            }
        }


        public R1csMatrix Build(int rowCount, int columnCount, CurveParameterSet curve, BaseMemoryPool pool)
        {
            if(rows.Count == 0)
            {
                //R1csMatrix requires at least one non-zero; a genuinely all-zero
                //matrix is degenerate, so synthesise a (0, 0) = 0 entry to satisfy
                //the invariant without changing satisfaction semantics.
                int[] singleRow = [0];
                int[] singleColumn = [0];
                byte[] zeroValue = new byte[scalarSizeBytes];
                return R1csMatrix.FromSortedTriples(singleRow, singleColumn, zeroValue, rowCount, columnCount, curve, pool);
            }

            int nonZeroCount = rows.Count;

            //Constraints arrive in ascending row order, but terms within a row
            //arrive in producer order; FromSortedTriples needs strictly-ascending
            //(row, column), so sort the index permutation lexicographically.
            int[] order = new int[nonZeroCount];
            for(int i = 0; i < nonZeroCount; i++)
            {
                order[i] = i;
            }

            Array.Sort(order, (x, y) =>
            {
                int byRow = rows[x].CompareTo(rows[y]);
                return byRow != 0 ? byRow : columns[x].CompareTo(columns[y]);
            });

            int[] sortedRows = new int[nonZeroCount];
            int[] sortedColumns = new int[nonZeroCount];
            byte[] sortedValues = new byte[nonZeroCount * scalarSizeBytes];
            byte[] flatValues = valueBytes.ToArray();
            for(int i = 0; i < nonZeroCount; i++)
            {
                int source = order[i];
                sortedRows[i] = rows[source];
                sortedColumns[i] = columns[source];
                Array.Copy(flatValues, source * scalarSizeBytes, sortedValues, i * scalarSizeBytes, scalarSizeBytes);
            }

            return R1csMatrix.FromSortedTriples(sortedRows, sortedColumns, sortedValues, rowCount, columnCount, curve, pool);
        }
    }
}
