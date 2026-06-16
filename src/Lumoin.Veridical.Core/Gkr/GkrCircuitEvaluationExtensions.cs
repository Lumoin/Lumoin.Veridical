using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// Every layer's wire values of one circuit evaluation, each table backed by a pooled buffer this
/// holder owns (dispose to return them). Index 0 is the circuit output table and index
/// <c>Count − 1</c> is the input table; the prover folds each layer's sumcheck over the table
/// below it.
/// </summary>
internal sealed class GkrWireTables: IDisposable
{
    private readonly IMemoryOwner<byte>[] owners;
    private readonly int[] lengths;


    public int Count => owners.Length;


    internal GkrWireTables(IMemoryOwner<byte>[] owners, int[] lengths)
    {
        this.owners = owners;
        this.lengths = lengths;
    }


    public ReadOnlyMemory<byte> Table(int index) => owners[index].Memory[..lengths[index]];


    public void Dispose()
    {
        foreach(IMemoryOwner<byte> owner in owners)
        {
            owner.Dispose();
        }
    }
}


/// <summary>
/// Evaluates a <see cref="GkrCircuit"/> on concrete inputs, producing every layer's wire table
/// in pooled storage.
/// </summary>
internal static class GkrCircuitEvaluationExtensions
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    public static GkrWireTables Evaluate(
        this GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        if(inputs.Length != circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"The circuit takes {circuit.InputCount} inputs ({circuit.InputCount * ScalarSize} bytes); received {inputs.Length}.", nameof(inputs));
        }

        int layerCount = circuit.Layers.Length;
        var owners = new IMemoryOwner<byte>[layerCount + 1];
        int[] lengths = new int[layerCount + 1];

        lengths[layerCount] = inputs.Length;
        owners[layerCount] = pool.Rent(inputs.Length);
        inputs.CopyTo(owners[layerCount].Memory.Span);

        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];

        for(int i = layerCount - 1; i >= 0; i--)
        {
            GkrLayer layer = circuit.Layers[i];
            ReadOnlySpan<byte> below = owners[i + 1].Memory.Span[..lengths[i + 1]];
            lengths[i] = layer.OutputCount * ScalarSize;
            owners[i] = pool.Rent(lengths[i]);
            Span<byte> outputs = owners[i].Memory.Span[..lengths[i]];
            outputs.Clear();
            foreach(GkrLayerTerm gate in layer.Terms)
            {
                multiply(below.Slice(gate.LeftWire * ScalarSize, ScalarSize), below.Slice(gate.RightWire * ScalarSize, ScalarSize), product, curve);
                multiply(gate.Coefficient.Span, product, term, curve);
                Span<byte> output = outputs.Slice(gate.OutputWire * ScalarSize, ScalarSize);
                add(output, term, sum, curve);
                sum.CopyTo(output);
            }
        }

        return new GkrWireTables(owners, lengths);
    }
}
