using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The per-layer input wire tables produced by evaluating the circuit on the witness column, the
/// reference's <c>ProverLayers::eval_circuit</c> output <c>in</c> for the single-copy case
/// (<c>nc == 1</c>). Index <c>ly</c> is the input wires of layer <c>ly</c>; the circuit output (the
/// output of layer 0) is held separately. Each table is <see cref="LongfellowSumcheckLayer.InputCount"/>
/// canonical scalars, one per wire (the single copy makes each table one column).
/// </summary>
/// <remarks>
/// The wire tables carry intermediate circuit values derived from the private witness, so they are pooled
/// by the library's default discipline and cleared on disposal.
/// </remarks>
internal sealed class LongfellowWireTables: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    private readonly int[] tableOffset;
    private readonly int[] tableLength;
    private readonly int outputOffset;
    private readonly int totalScalars;

    private IMemoryOwner<byte>? buffer;


    internal LongfellowWireTables(LongfellowSumcheckCircuit circuit, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(pool);

        int layerCount = circuit.LayerCount;
        tableOffset = new int[layerCount];
        tableLength = new int[layerCount];

        int offset = 0;
        for(int layer = 0; layer < layerCount; layer++)
        {
            tableOffset[layer] = offset;
            tableLength[layer] = circuit.Layers[layer].InputCount;
            offset += tableLength[layer];
        }

        outputOffset = offset;
        offset += circuit.OutputCount;

        totalScalars = offset;
        buffer = pool.Rent(Math.Max(totalScalars, 1) * ScalarSize);
        buffer.Memory.Span[..(Math.Max(totalScalars, 1) * ScalarSize)].Clear();
    }


    /// <summary>Returns the input wire table of layer <paramref name="layer"/>.</summary>
    public Span<byte> Table(int layer) =>
        Storage.Slice(tableOffset[layer] * ScalarSize, tableLength[layer] * ScalarSize);


    /// <summary>Returns the circuit output table (the output of layer 0).</summary>
    public Span<byte> OutputTable() =>
        Storage[(outputOffset * ScalarSize)..];


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = buffer;
        if(local is not null)
        {
            buffer = null;
            local.Memory.Span[..(Math.Max(totalScalars, 1) * ScalarSize)].Clear();
            local.Dispose();
        }
    }


    private Span<byte> Storage =>
        (buffer ?? throw new ObjectDisposedException(nameof(LongfellowWireTables))).Memory.Span[..(Math.Max(totalScalars, 1) * ScalarSize)];
}
