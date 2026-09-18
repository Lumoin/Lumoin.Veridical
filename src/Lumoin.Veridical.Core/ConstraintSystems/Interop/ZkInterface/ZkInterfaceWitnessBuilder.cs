using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// An <see cref="IZkInterfaceMessageSink"/> that folds a decoded
/// ZkInterface stream into a <see cref="RawR1csWitness"/>.
/// </summary>
/// <remarks>
/// <para>
/// ZkInterface splits the variable assignment across two messages: the
/// <c>CircuitHeader.instance_variables</c> hold the public (instance)
/// values, and a <c>Witness.assigned_variables</c> holds the private
/// values (excluding the constant one). Under the reader's
/// PublicInputCount = 0 convention, the witness Veridical expects is the
/// whole <c>z[1..]</c> — every variable but the constant — so this builder
/// scatters both sources into one dense vector keyed by column = variable
/// ID (matching <see cref="ZkInterfaceR1csInstanceBuilder"/>), then drops
/// column 0. Columns that no message assigns default to zero.
/// </para>
/// <para>
/// The field is reconciled exactly as for the instance: a declared
/// <c>field_maximum</c> must match the curve, and an undeclared field is
/// rejected. Constraint callbacks are ignored.
/// </para>
/// <para>
/// The dense <c>z[1..]</c> vector is sized purely from the declared
/// <c>free_variable_id</c> and the referenced variable ids, both of which a
/// hostile stream controls independently of how many bytes it actually
/// carries. To keep the allocation bounded by the input, the reader supplies
/// the source byte length as the <c>maxColumnCount</c> ceiling: a stream of
/// <c>N</c> bytes cannot describe more than <c>N</c> columns — a complete
/// witness assigns every non-constant variable, and each assignment costs at
/// least its 8-byte id — so a larger declared column space is rejected as a
/// memory-amplification attempt rather than rented. The effective memory
/// ceiling is therefore <c>scalarSizeBytes × N</c> (the dense buffer holds one
/// scalar per column), capped to a single addressable span. The ceiling assumes
/// the decoder reads the same uncompressed bytes it is measured against; the
/// built-in decoder does, and a swapped-in decoder must not expand its input.
/// </para>
/// <para>
/// A consequence is that Veridical requires dense-ish variable ids: a witness
/// whose <c>free_variable_id</c> or referenced ids sit far above the count of
/// assigned variables (a legal but sparse encoding) is rejected. Conformant
/// producers do not emit such streams, and the dense-scatter model would serve
/// them poorly regardless.
/// </para>
/// </remarks>
internal sealed class ZkInterfaceWitnessBuilder: IZkInterfaceMessageSink
{
    /// <summary>The one column reserved for the constant, excluded from the dense <c>z[1..]</c> vector.</summary>
    private const int ConstantColumnCount = 1;

    /// <summary>The constant's column index, implicit in <c>z[0]</c> and never scattered into the dense vector.</summary>
    private const int ConstantColumn = 0;

    /// <summary>The curve identifying the scalar field that each assigned value is reconciled and scattered against.</summary>
    private CurveParameterSet Curve { get; }

    /// <summary>The pool used to rent the dense witness buffer and to construct the returned witness.</summary>
    private BaseMemoryPool Pool { get; }

    /// <summary>The canonical byte width of one scalar under <see cref="Curve"/>, and the stride between scattered values.</summary>
    private int ScalarSizeBytes { get; }

    /// <summary>The largest column count the source can justify, bounding the dense witness allocation. See the type remarks.</summary>
    private int MaxColumnCount { get; }

    /// <summary>One recorded column per assignment, in arrival order, index-aligned with <see cref="ValueBytes"/>.</summary>
    private List<int> Columns { get; } = new();

    /// <summary>The canonical big-endian value bytes for each assignment, <see cref="ScalarSizeBytes"/> bytes per entry, in the same arrival order as <see cref="Columns"/>.</summary>
    private List<byte> ValueBytes { get; } = new();

    /// <summary>Whether a <c>CircuitHeader.field_maximum</c> has already been observed, so a repeated one can be rejected.</summary>
    private bool fieldSeen;

    /// <summary>Whether a header's <c>free_variable_id</c> has been observed at least once.</summary>
    private bool freeVariableIdSeen;

    /// <summary>The largest <c>free_variable_id</c> observed across every header seen so far.</summary>
    private ulong freeVariableId;

    /// <summary>The largest column assigned so far by <see cref="Assign"/>, or -1 when nothing has been assigned yet.</summary>
    private long maxColumn = -1;


    /// <summary>Initialises a builder that scatters ZkInterface instance and witness values into a dense <c>z[1..]</c> vector.</summary>
    /// <param name="curve">The curve identifying the scalar field.</param>
    /// <param name="pool">The pool the dense witness buffer is rented from.</param>
    /// <param name="maxColumnCount">
    /// The largest column count the source can justify — the reader passes the
    /// source byte length so the dense witness allocation stays bounded by the
    /// input. See the type remarks.
    /// </param>
    public ZkInterfaceWitnessBuilder(CurveParameterSet curve, BaseMemoryPool pool, int maxColumnCount)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(maxColumnCount);

        this.Curve = curve;
        this.Pool = pool;
        this.MaxColumnCount = maxColumnCount;
        ScalarSizeBytes = R1csMatrix.GetValueByteSize(curve);
    }


    /// <summary>Records the header's <c>field_maximum</c>, rejecting a curve mismatch or a repeated declaration.</summary>
    public void OnFieldMaximum(ReadOnlySpan<byte> fieldMaximumLittleEndian)
    {
        if(fieldSeen)
        {
            throw new ArgumentException("ZkInterface stream declares more than one CircuitHeader field_maximum.");
        }

        fieldSeen = true;
        ZkInterfaceFieldReconciler.ThrowIfFieldDoesNotMatch(fieldMaximumLittleEndian, Curve);
    }


    /// <summary>Widens the tracked <c>free_variable_id</c> to the largest value observed so far.</summary>
    public void OnFreeVariableId(ulong freeVariableId)
    {
        this.freeVariableId = Math.Max(this.freeVariableId, freeVariableId);
        freeVariableIdSeen = true;
    }


    /// <summary>Scatters one <c>CircuitHeader.instance_variables</c> entry by its column id.</summary>
    public void OnInstanceVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian) =>
        Assign(variableId, valueLittleEndian);


    /// <summary>Scatters one <c>Witness.assigned_variables</c> entry by its column id.</summary>
    public void OnWitnessVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian) =>
        Assign(variableId, valueLittleEndian);


    /// <summary>Assembles the scattered assignments into the dense <c>z[1..]</c> witness vector.</summary>
    public RawR1csWitness Build()
    {
        if(!fieldSeen)
        {
            throw ZkInterfaceFieldReconciler.AbsentFieldException(Curve);
        }

        int columnCount = ResolveColumnCount();
        int witnessVariableCount = columnCount - ConstantColumnCount;
        if(witnessVariableCount < 1)
        {
            throw new ArgumentException("ZkInterface witness has no variables beyond the constant one.");
        }

        //Scatter into a pooled buffer (witness values are sensitive); FromCanonical
        //copies it into its own pooled buffer, so this one is released here.
        using IMemoryOwner<byte> owner = Pool.Rent(witnessVariableCount * ScalarSizeBytes);
        Span<byte> z = owner.Memory.Span[..(witnessVariableCount * ScalarSizeBytes)];
        //The pool is the caller's and may not zero a fresh rental, so the library clears it here before scattering sensitive witness values in.
        z.Clear();

        //Zero-copy view over the accumulated big-endian values.
        ReadOnlySpan<byte> values = CollectionsMarshal.AsSpan(ValueBytes);
        for(int i = 0; i < Columns.Count; i++)
        {
            int column = Columns[i];

            //Column 0 is the constant one; it is implicit in z[0] and excluded
            //from z[1..]. A producer should not assign it, but skip it defensively.
            if(column == ConstantColumn)
            {
                continue;
            }

            values.Slice(i * ScalarSizeBytes, ScalarSizeBytes).CopyTo(z[((column - 1) * ScalarSizeBytes)..]);
        }

        return RawR1csWitness.FromCanonical(z, Curve, Pool);
    }


    /// <summary>Resolves the dense witness column count from the header and the assigned ids, rejecting one the source cannot justify.</summary>
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

        int fromAssignedIds = maxColumn < 0 ? 0 : checked((int)(maxColumn + 1));
        int columnCount = Math.Max(fromFreeVariableId, fromAssignedIds);

        //Anti-amplification: the dense z[1..] vector is (columnCount - 1) scalars
        //wide, sized from the declared free_variable_id and the referenced ids
        //alone — both decoupled from how many bytes arrived. A source of
        //maxColumnCount bytes cannot describe more columns than that, so a larger
        //count is a memory-amplification attempt; reject it as malformed rather
        //than rent an unbounded buffer.
        if(columnCount > MaxColumnCount)
        {
            throw new ArgumentException(
                $"ZkInterface witness declares a {columnCount}-column variable space that the {MaxColumnCount}-byte source cannot describe; rejecting to bound witness allocation.");
        }

        //Even for a source large enough to justify this many columns, the dense
        //buffer is (columnCount - 1) * ScalarSizeBytes bytes and must be
        //addressable as one span; guard the Int32 product before Pool.Rent.
        if((long)(columnCount - ConstantColumnCount) * ScalarSizeBytes > Array.MaxLength)
        {
            throw new ArgumentException(
                $"ZkInterface witness variable space of {columnCount} columns exceeds the addressable dense-buffer size.");
        }

        return columnCount;
    }


    /// <summary>Records one (variable, value) pair, bounding both the resolved column and the accumulator by the addressable range.</summary>
    private void Assign(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
    {
        //The resolved column count is maxColumn + 1 and must fit in Int32; a variable id at
        //Int32.MaxValue would need Int32.MaxValue + 1 columns, overflowing the checked cast in
        //ResolveColumnCount. Reject it here as an out-of-range id rather than as an OverflowException.
        if(variableId >= int.MaxValue)
        {
            throw new ArgumentException($"ZkInterface variable id {variableId} exceeds the addressable column range.");
        }

        //Bound the accumulator here, at intake, not only the dense buffer in Build:
        //assignments accrue ScalarSizeBytes into ValueBytes each, and a variable_ids
        //vector padded to tens of millions of entries (even all aliasing one column)
        //would grow ValueBytes past Array.MaxLength and throw an undocumented
        //OutOfMemoryException mid-decode, before Build's ceiling is ever consulted. A
        //well-formed witness assigns at most columnCount - 1 values, and a columnCount
        //that large is itself rejected in ResolveColumnCount, so this never trips on a
        //valid stream.
        if((long)(Columns.Count + 1) * ScalarSizeBytes > Array.MaxLength)
        {
            throw new ArgumentException("ZkInterface witness assigns more values than an addressable buffer can hold.");
        }

        int column = (int)variableId;
        Columns.Add(column);
        if(column > maxColumn)
        {
            maxColumn = column;
        }

        Span<byte> bigEndian = stackalloc byte[ScalarSizeBytes];
        ZkInterfaceScalar.WriteCanonicalBigEndian(valueLittleEndian, bigEndian);
        for(int j = 0; j < ScalarSizeBytes; j++)
        {
            ValueBytes.Add(bigEndian[j]);
        }
    }
}
