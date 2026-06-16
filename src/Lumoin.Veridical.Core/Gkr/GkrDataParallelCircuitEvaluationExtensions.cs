using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// Evaluates <c>copyCount</c> data-parallel copies of a <see cref="GkrCircuit"/>: the same
/// per-copy wiring applied to each copy's slice of the inputs. Wire tables are laid out copy-major
/// (<c>table[c·width + h]</c>, the copy index in the high bits), the layout the data-parallel
/// prover's copy-variable rounds fold.
/// </summary>
internal static class GkrDataParallelCircuitEvaluationExtensions
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    public static GkrWireTables EvaluateDataParallel(
        this GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        int copyCount,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);
        if(copyCount < 2 || !BitOperations.IsPow2(copyCount))
        {
            throw new ArgumentOutOfRangeException(nameof(copyCount), copyCount, "The copy count must be a power of two of at least 2.");
        }

        if(inputs.Length != copyCount * circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"{copyCount} copies of {circuit.InputCount} inputs need {copyCount * circuit.InputCount * ScalarSize} bytes; received {inputs.Length}.", nameof(inputs));
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
            int widthBelow = circuit.WidthBelow(i);
            ReadOnlySpan<byte> below = owners[i + 1].Memory.Span[..lengths[i + 1]];
            lengths[i] = copyCount * layer.OutputCount * ScalarSize;
            owners[i] = pool.Rent(lengths[i]);
            Span<byte> outputs = owners[i].Memory.Span[..lengths[i]];
            outputs.Clear();
            for(int c = 0; c < copyCount; c++)
            {
                ReadOnlySpan<byte> belowCopy = below.Slice(c * widthBelow * ScalarSize, widthBelow * ScalarSize);
                Span<byte> outputCopy = outputs.Slice(c * layer.OutputCount * ScalarSize, layer.OutputCount * ScalarSize);
                foreach(GkrLayerTerm gate in layer.Terms)
                {
                    multiply(belowCopy.Slice(gate.LeftWire * ScalarSize, ScalarSize), belowCopy.Slice(gate.RightWire * ScalarSize, ScalarSize), product, curve);
                    multiply(gate.Coefficient.Span, product, term, curve);
                    Span<byte> output = outputCopy.Slice(gate.OutputWire * ScalarSize, ScalarSize);
                    add(output, term, sum, curve);
                    sum.CopyTo(output);
                }
            }
        }

        return new GkrWireTables(owners, lengths);
    }
}
