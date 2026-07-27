using System;
using System.Buffers.Binary;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

/// <summary>
/// The structural circuit identifier, a faithful port of google/longfellow-zk's <c>circuit_id</c>
/// (<c>lib/sumcheck/circuit_id.h</c>): a SHA-256 over the circuit's structure — the field identity,
/// the size header, and every layer's corners — independent of any serialization format. The
/// transcript absorbs this id first on every prover and verifier side, so it is the value that
/// cryptographically binds a proof to its circuit.
/// </summary>
/// <remarks>
/// The byte layout is pinned by the reference: every integer is a little-endian 64-bit word
/// (<c>SHA256::Update8</c>); a characteristic-two field contributes the marker 2 and its bit count,
/// an odd prime field the marker 1 and the little-endian serialization of −1 (the modulus less
/// one); each corner contributes its gate and hand indices as three words and its coefficient as
/// the field's little-endian <c>to_bytes_field</c> serialization.
/// </remarks>
internal static class LongfellowCircuitIdentifier
{
    //The reference's field markers: 0x2 for characteristic-two fields, 0x1 for odd prime fields.
    private const ulong CharacteristicTwoMarker = 0x2;
    private const ulong OddPrimeMarker = 0x1;


    /// <summary>
    /// Computes the 32-byte structural id over a compiled circuit's layers.
    /// </summary>
    /// <param name="field">The field-operation bundle supplying the field identity and element serialization.</param>
    /// <param name="outputCount">The output wire count (<c>nv</c>).</param>
    /// <param name="outputLogCount">The output binding rounds (<c>logv</c>).</param>
    /// <param name="copyCount">The copy count (<c>nc</c>).</param>
    /// <param name="copyRounds">The copy binding rounds (<c>logc</c>).</param>
    /// <param name="inputCount">The input count (<c>ninputs</c>).</param>
    /// <param name="publicInputCount">The public input count (<c>npub_in</c>).</param>
    /// <param name="subfieldBoundary">The least input wire not known to lie in the subfield.</param>
    /// <param name="layers">The layers in walk order with their canonicalized corners.</param>
    /// <param name="hashFactory">The incremental SHA-256 factory.</param>
    /// <returns>The 32-byte id.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static byte[] Compute(
        LongfellowCompilerFieldOperations field,
        int outputCount,
        int outputLogCount,
        int copyCount,
        int copyRounds,
        int inputCount,
        int publicInputCount,
        int subfieldBoundary,
        LongfellowSumcheckLayer[] layers,
        LongfellowIncrementalHashFactory hashFactory)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(layers);
        ArgumentNullException.ThrowIfNull(hashFactory);

        ILongfellowIncrementalHash hash = hashFactory();

        Span<byte> word = stackalloc byte[sizeof(ulong)];
        Span<byte> element = stackalloc byte[Scalar.SizeBytes];

        if(field.IsCharacteristicTwo)
        {
            UpdateWord(hash, word, CharacteristicTwoMarker);
            UpdateWord(hash, word, (ulong)field.BitCount);
        }
        else
        {
            UpdateWord(hash, word, OddPrimeMarker);
            field.WriteLittleEndian(field.MinusOne.Span, element);
            hash.Update(element[..field.ElementBytes]);
        }

        UpdateWord(hash, word, (ulong)outputCount);
        UpdateWord(hash, word, (ulong)outputLogCount);
        UpdateWord(hash, word, (ulong)copyCount);
        UpdateWord(hash, word, (ulong)copyRounds);
        UpdateWord(hash, word, (ulong)layers.Length);
        UpdateWord(hash, word, (ulong)inputCount);
        UpdateWord(hash, word, (ulong)publicInputCount);
        UpdateWord(hash, word, (ulong)subfieldBoundary);

        foreach(LongfellowSumcheckLayer layer in layers)
        {
            UpdateWord(hash, word, (ulong)layer.InputCount);
            UpdateWord(hash, word, (ulong)layer.HandRounds);
            UpdateWord(hash, word, (ulong)layer.TermCount);

            foreach(LongfellowSumcheckQuadTerm corner in layer.QuadTerms)
            {
                UpdateWord(hash, word, (ulong)corner.GateIndex);
                UpdateWord(hash, word, (ulong)corner.LeftIndex);
                UpdateWord(hash, word, (ulong)corner.RightIndex);
                field.WriteLittleEndian(corner.Coefficient.Span, element);
                hash.Update(element[..field.ElementBytes]);
            }
        }

        var id = new byte[LongfellowSumcheckCircuit.IdLength];
        hash.FinalizeInto(id);

        return id;
    }


    /// <summary>
    /// Absorbs one little-endian 64-bit word (<c>Update8</c>).
    /// </summary>
    /// <param name="hash">The running hash.</param>
    /// <param name="scratch">An eight-byte scratch span.</param>
    /// <param name="value">The word to absorb.</param>
    private static void UpdateWord(ILongfellowIncrementalHash hash, Span<byte> scratch, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(scratch, value);
        hash.Update(scratch);
    }
}
