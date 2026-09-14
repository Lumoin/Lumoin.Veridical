using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;

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
/// (<see cref="RawR1csInstance.PublicInputCount"/> = 0); a genuine
/// instance/witness split is deferred, since promoting instance variables
/// to first-class public inputs would require the public columns to
/// occupy positions <c>1..p</c> contiguously, which arbitrary ZkInterface
/// ids do not guarantee.
/// </para>
/// </remarks>
internal sealed class ZkInterfaceR1csInstanceBuilder: IZkInterfaceMessageSink
{
    /// <summary>The curve identifying the scalar field of the decoded stream.</summary>
    private readonly CurveParameterSet curve;

    /// <summary>The pool supplying staging buffers and the constructed instance's storage.</summary>
    private readonly BaseMemoryPool pool;

    /// <summary>The canonical byte width of each coefficient.</summary>
    private readonly int scalarSizeBytes;

    /// <summary>The accumulated terms of the left matrix.</summary>
    private readonly TripleAccumulator aTriples;

    /// <summary>The accumulated terms of the middle matrix.</summary>
    private readonly TripleAccumulator bTriples;

    /// <summary>The accumulated terms of the right matrix.</summary>
    private readonly TripleAccumulator cTriples;

    /// <summary>Whether the stream has declared its field maximum.</summary>
    private bool fieldSeen;

    /// <summary>Whether the stream has declared a free variable ID.</summary>
    private bool freeVariableIdSeen;

    /// <summary>The widest variable space declared by the stream.</summary>
    private ulong freeVariableId;

    /// <summary>The greatest referenced variable ID, or minus one when none has been seen.</summary>
    private long maxVariableId = -1;

    /// <summary>The current constraint row, or minus one before the first constraint.</summary>
    private int currentRow = -1;

    /// <summary>The number of constraints begun in the stream.</summary>
    private int constraintCount;


    /// <summary>Creates an empty instance builder for the supplied curve and memory pool.</summary>
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


    /// <summary>Checks the stream's single field maximum against the declared curve.</summary>
    public void OnFieldMaximum(ReadOnlySpan<byte> fieldMaximumLittleEndian)
    {
        if(fieldSeen)
        {
            throw new ArgumentException("ZkInterface stream declares more than one CircuitHeader field_maximum.");
        }

        fieldSeen = true;
        ZkInterfaceFieldReconciler.ThrowIfFieldDoesNotMatch(fieldMaximumLittleEndian, curve);
    }


    /// <summary>Records the widest declared variable space.</summary>
    public void OnFreeVariableId(ulong freeVariableId)
    {
        //A complete circuit carries a single header; tolerate repeats by
        //keeping the widest declared variable space.
        this.freeVariableId = Math.Max(this.freeVariableId, freeVariableId);
        freeVariableIdSeen = true;
    }


    /// <summary>Tracks an instance variable's ID under the convention that all nonconstant variables are private.</summary>
    public void OnInstanceVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
    {
        //Values are ignored under the PublicInputCount = 0 convention; the ID
        //still participates in sizing the column space.
        TrackVariableId(variableId);
    }


    /// <summary>Advances to the next constraint row.</summary>
    public void BeginConstraint()
    {
        currentRow++;
        constraintCount++;
    }


    /// <summary>Appends a term to the selected matrix at the current constraint row.</summary>
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


    /// <summary>Resolves a positive column count covering all declared and referenced variable IDs.</summary>
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


    /// <summary>Validates a variable ID, widens the referenced variable space, and returns its column.</summary>
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


    /// <summary>Returns the accumulator for a recognised matrix selector.</summary>
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
        /// <summary>The canonical byte width of every coefficient stored in this accumulator.</summary>
        private readonly int scalarSizeBytes;

        /// <summary>The constraint row for each encoded term, in arrival order.</summary>
        private readonly List<int> rows = new();

        /// <summary>The variable column for each encoded term, in arrival order.</summary>
        private readonly List<int> columns = new();

        /// <summary>The canonical big-endian coefficients, one scalar per encoded term in arrival order.</summary>
        private readonly List<byte> valueBytes = new();


        /// <summary>Creates an empty accumulator whose coefficients have the supplied canonical byte width.</summary>
        public TripleAccumulator(int scalarSizeBytes)
        {
            this.scalarSizeBytes = scalarSizeBytes;
        }


        /// <summary>Appends a term after bounding the accumulated bytes and converting its coefficient to canonical big-endian.</summary>
        public void Add(int row, int column, ReadOnlySpan<byte> coefficientLittleEndian)
        {
            //Bound the byte accumulator at intake, mirroring the witness builder's Assign cap:
            //each term appends scalarSizeBytes into valueBytes, and the decode-work budget bounds
            //the number of terms by the source byte length, not by the bytes they accrue. Because
            //an aliased constraints/ids vector amortises one 4-byte offset element across many
            //terms, a bounded stream can still drive valueBytes past Array.MaxLength, where the
            //List<byte> backing-array resize throws an undocumented OutOfMemoryException mid-decode.
            //Reject with the documented ArgumentException first; a conformant constraint system's
            //per-matrix non-zero count stays far below this ceiling.
            if((long)(rows.Count + 1) * scalarSizeBytes > Array.MaxLength)
            {
                throw new ArgumentException("ZkInterface constraint system accumulates more coefficient bytes than an addressable buffer can hold.");
            }

            rows.Add(row);
            columns.Add(column);

            Span<byte> bigEndian = stackalloc byte[scalarSizeBytes];
            ZkInterfaceScalar.WriteCanonicalBigEndian(coefficientLittleEndian, bigEndian);
            for(int j = 0; j < scalarSizeBytes; j++)
            {
                valueBytes.Add(bigEndian[j]);
            }
        }


        /// <summary>Sorts terms by row and column and constructs a matrix, supplying one zero entry when no terms are encoded.</summary>
        /// <remarks>
        /// Coefficients are staged in a pooled buffer and copied into the matrix's own storage by
        /// <see cref="R1csMatrix.FromSortedTriples"/>. The staging rental is disposed when this method exits.
        /// </remarks>
        public R1csMatrix Build(int rowCount, int columnCount, CurveParameterSet curve, BaseMemoryPool pool)
        {
            if(rows.Count == 0)
            {
                //R1csMatrix requires at least one non-zero; a genuinely all-zero
                //matrix is degenerate, so synthesise a (0, 0) = 0 entry to satisfy
                //the invariant without changing satisfaction semantics.
                int[] singleRow = [0];
                int[] singleColumn = [0];
                using IMemoryOwner<byte> zeroValueOwner = pool.Rent(scalarSizeBytes);
                Span<byte> zeroValue = zeroValueOwner.Memory.Span[..scalarSizeBytes];
                zeroValue.Clear();

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
            int sortedValuesLength = nonZeroCount * scalarSizeBytes;
            using IMemoryOwner<byte> sortedValuesOwner = pool.Rent(sortedValuesLength);
            Span<byte> sortedValues = sortedValuesOwner.Memory.Span[..sortedValuesLength];
            ReadOnlySpan<byte> flatValues = CollectionsMarshal.AsSpan(valueBytes);
            for(int i = 0; i < nonZeroCount; i++)
            {
                int source = order[i];
                sortedRows[i] = rows[source];
                sortedColumns[i] = columns[source];
                flatValues.Slice(source * scalarSizeBytes, scalarSizeBytes)
                    .CopyTo(sortedValues.Slice(i * scalarSizeBytes, scalarSizeBytes));
            }

            return R1csMatrix.FromSortedTriples(sortedRows, sortedColumns, sortedValues, rowCount, columnCount, curve, pool);
        }
    }
}
