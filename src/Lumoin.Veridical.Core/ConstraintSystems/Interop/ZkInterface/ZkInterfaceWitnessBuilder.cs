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
/// </remarks>
internal sealed class ZkInterfaceWitnessBuilder: IZkInterfaceMessageSink
{
    private readonly CurveParameterSet curve;
    private readonly SensitiveMemoryPool<byte> pool;
    private readonly int scalarSizeBytes;

    private readonly List<int> columns = new();
    private readonly List<byte> valueBytes = new();

    private bool fieldSeen;
    private bool freeVariableIdSeen;
    private ulong freeVariableId;
    private long maxColumn = -1;


    public ZkInterfaceWitnessBuilder(CurveParameterSet curve, SensitiveMemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        this.curve = curve;
        this.pool = pool;
        scalarSizeBytes = R1csMatrix.GetValueByteSize(curve);
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
        this.freeVariableId = Math.Max(this.freeVariableId, freeVariableId);
        freeVariableIdSeen = true;
    }


    public void OnInstanceVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian) =>
        Assign(variableId, valueLittleEndian);


    public void OnWitnessVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian) =>
        Assign(variableId, valueLittleEndian);


    /// <summary>Assembles the scattered assignments into the dense <c>z[1..]</c> witness vector.</summary>
    public RawR1csWitness Build()
    {
        if(!fieldSeen)
        {
            throw ZkInterfaceFieldReconciler.AbsentFieldException(curve);
        }

        int columnCount = ResolveColumnCount();
        int witnessVariableCount = columnCount - 1;
        if(witnessVariableCount < 1)
        {
            throw new ArgumentException("ZkInterface witness has no variables beyond the constant one.");
        }

        //Scatter into a pooled buffer (witness values are sensitive); FromCanonical
        //copies it into its own pooled buffer, so this one is released here.
        using IMemoryOwner<byte> owner = pool.Rent(witnessVariableCount * scalarSizeBytes);
        Span<byte> z = owner.Memory.Span[..(witnessVariableCount * scalarSizeBytes)];
        z.Clear();

        //Zero-copy view over the accumulated big-endian values.
        ReadOnlySpan<byte> values = CollectionsMarshal.AsSpan(valueBytes);
        for(int i = 0; i < columns.Count; i++)
        {
            int column = columns[i];

            //Column 0 is the constant one; it is implicit in z[0] and excluded
            //from z[1..]. A producer should not assign it, but skip it defensively.
            if(column == 0)
            {
                continue;
            }

            values.Slice(i * scalarSizeBytes, scalarSizeBytes).CopyTo(z[((column - 1) * scalarSizeBytes)..]);
        }

        return RawR1csWitness.FromCanonical(z, curve, pool);
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

        int fromAssignedIds = maxColumn < 0 ? 0 : checked((int)(maxColumn + 1));
        return Math.Max(fromFreeVariableId, fromAssignedIds);
    }


    private void Assign(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
    {
        if(variableId > int.MaxValue)
        {
            throw new ArgumentException($"ZkInterface variable id {variableId} exceeds the addressable column range.");
        }

        int column = (int)variableId;
        columns.Add(column);
        if(column > maxColumn)
        {
            maxColumn = column;
        }

        Span<byte> bigEndian = stackalloc byte[scalarSizeBytes];
        ZkInterfaceScalar.WriteCanonicalBigEndian(valueLittleEndian, bigEndian);
        for(int j = 0; j < scalarSizeBytes; j++)
        {
            valueBytes.Add(bigEndian[j]);
        }
    }
}
