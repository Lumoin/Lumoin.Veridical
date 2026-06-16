using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// One term of a GKR layer: output wire <see cref="OutputWire"/> accumulates
/// <c>Coefficient · W[LeftWire] · W[RightWire]</c> over the wires of the layer below. This is the
/// Longfellow <c>Quad</c> gate shape — a multiplication gate is a term over two real wires, and a
/// linear term routes one hand through a constant-one wire. <see cref="Coefficient"/> is a
/// canonical 32-byte field element.
/// </summary>
internal readonly record struct GkrLayerTerm(int OutputWire, int LeftWire, int RightWire, ReadOnlyMemory<byte> Coefficient);


/// <summary>
/// One GKR layer: <see cref="OutputCount"/> output wires (a power of two), each defined as the
/// sum of its <see cref="Terms"/> over the wires of the layer below.
/// </summary>
internal sealed class GkrLayer
{
    public GkrLayerTerm[] Terms { get; }

    public int OutputCount { get; }


    public GkrLayer(GkrLayerTerm[] terms, int outputCount)
    {
        ArgumentNullException.ThrowIfNull(terms);
        if(outputCount < 2 || !BitOperations.IsPow2(outputCount))
        {
            throw new ArgumentOutOfRangeException(nameof(outputCount), outputCount, "A layer's output count must be a power of two of at least 2.");
        }

        foreach(GkrLayerTerm term in terms)
        {
            if(term.OutputWire < 0 || term.OutputWire >= outputCount)
            {
                throw new ArgumentException($"Term output wire {term.OutputWire} is outside [0, {outputCount}).", nameof(terms));
            }

            if(term.Coefficient.Length != Scalar.SizeBytes)
            {
                throw new ArgumentException($"Term coefficients must be {Scalar.SizeBytes} canonical bytes; received {term.Coefficient.Length}.", nameof(terms));
            }
        }

        Terms = terms;
        OutputCount = outputCount;
    }
}


/// <summary>
/// A layered GKR circuit over a delegate-supplied field: <see cref="Layers"/>[0] is the output
/// layer and each layer's terms reference the wires of the layer below it —
/// <see cref="Layers"/>[i + 1]'s outputs, or the <see cref="InputCount"/> input wires below the
/// last layer. The layered form is what makes the GKR prover linear: each layer is proven by one
/// product sumcheck over <c>eq · W_left · W_right</c> and the claim walks down to the inputs,
/// instead of the whole circuit being flattened into one constraint system.
/// </summary>
internal sealed class GkrCircuit
{
    public GkrLayer[] Layers { get; }

    public int InputCount { get; }


    public GkrCircuit(GkrLayer[] layers, int inputCount)
    {
        ArgumentNullException.ThrowIfNull(layers);
        if(layers.Length == 0)
        {
            throw new ArgumentException("A circuit needs at least one layer.", nameof(layers));
        }

        if(inputCount < 2 || !BitOperations.IsPow2(inputCount))
        {
            throw new ArgumentOutOfRangeException(nameof(inputCount), inputCount, "The input count must be a power of two of at least 2.");
        }

        for(int i = 0; i < layers.Length; i++)
        {
            int widthBelow = i == layers.Length - 1 ? inputCount : layers[i + 1].OutputCount;
            foreach(GkrLayerTerm term in layers[i].Terms)
            {
                if(term.LeftWire < 0 || term.LeftWire >= widthBelow || term.RightWire < 0 || term.RightWire >= widthBelow)
                {
                    throw new ArgumentException($"Layer {i} references wire ({term.LeftWire}, {term.RightWire}) outside [0, {widthBelow}).", nameof(layers));
                }
            }
        }

        Layers = layers;
        InputCount = inputCount;
    }


    //The number of wires feeding the given layer (the layer below's outputs, or the inputs).
    public int WidthBelow(int layerIndex) =>
        layerIndex == Layers.Length - 1 ? InputCount : Layers[layerIndex + 1].OutputCount;
}
