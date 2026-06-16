using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The zk sumcheck transcript, a faithful port of the <c>logc == 0</c> subset of google/longfellow-zk's
/// <c>Proof&lt;Field&gt;</c> / <c>LayerProof&lt;Field&gt;</c> (<c>lib/sumcheck/circuit.h</c>) that the
/// <c>write_sc_proof</c> / <c>read_sc_proof</c> segment carries (<c>lib/zk/zk_proof.h</c>). Per layer it
/// holds the two hands' degree-3 round polynomials <c>hp[hand][round]</c> and the two next-layer claims
/// <c>wc[0]</c>, <c>wc[1]</c>. The copy-binding polynomials <c>cp</c> are absent because the wire segment
/// requires <c>logc == 0</c>.
/// </summary>
/// <remarks>
/// <para>
/// A round polynomial is a <c>Poly&lt;3, Field&gt;</c> — three field elements <c>t_[0]</c>, <c>t_[1]</c>,
/// <c>t_[2]</c>, the Lagrange values at evaluation points <c>{0, 1, g}</c>. The wire only transmits
/// <c>t_[0]</c> and <c>t_[2]</c>: <c>t_[1] = p(1)</c> is implied by the sumcheck constraint
/// <c>claim = p(0) + p(1)</c> and is omitted (the k != 1 optimization). A proof parsed from the wire has
/// <c>t_[1]</c> set to zero; the verifier reconstructs it from the running claim.
/// </para>
/// <para>
/// The polynomials and claims are stored as 32-byte big-endian canonical scalars (the codebase's
/// <see cref="Scalar"/> representation), the same packing the Ligero proof uses, so the GF(2^128)
/// little-endian wire bytes round-trip through the existing <c>to_bytes_field</c> conversion. Disposable:
/// the single pooled backing buffer is cleared on disposal. The round polynomials are public prover
/// messages, but the proof is pooled by the library's default discipline.
/// </para>
/// </remarks>
internal sealed class LongfellowSumcheckProof: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    //A round polynomial is degree-3: three evaluation points t_[0], t_[1], t_[2].
    internal const int RoundPolynomialPoints = 3;

    //The two hands (left = 0, right = 1) bound per round.
    internal const int HandCount = 2;

    //The two next-layer claims wc[0], wc[1] each layer ends with.
    internal const int ClaimCount = 2;

    private readonly int[] handRoundsPerLayer;
    private readonly int[] layerOffset;
    private readonly int totalScalars;

    private IMemoryOwner<byte>? buffer;


    /// <summary>The layer count (<c>nl</c>).</summary>
    public int LayerCount => handRoundsPerLayer.Length;


    /// <summary>Returns the number of hand binding rounds (<c>logw</c>) of layer <paramref name="layer"/>.</summary>
    public int HandRounds(int layer) => handRoundsPerLayer[layer];


    internal LongfellowSumcheckProof(LongfellowSumcheckCircuit circuit, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(pool);

        int layerCount = circuit.LayerCount;
        handRoundsPerLayer = new int[layerCount];
        layerOffset = new int[layerCount];

        int offset = 0;
        for(int layer = 0; layer < layerCount; layer++)
        {
            handRoundsPerLayer[layer] = circuit.Layers[layer].HandRounds;
            layerOffset[layer] = offset;
            offset += LayerScalars(handRoundsPerLayer[layer]);
        }

        totalScalars = offset;
        buffer = pool.Rent(totalScalars * ScalarSize);
        buffer.Memory.Span[..(totalScalars * ScalarSize)].Clear();
    }


    /// <summary>
    /// Returns the canonical scalar bytes of round polynomial point <paramref name="point"/> for
    /// <paramref name="hand"/>, <paramref name="round"/> of <paramref name="layer"/>.
    /// </summary>
    public ReadOnlySpan<byte> RoundPolynomialPoint(int layer, int hand, int round, int point) =>
        Storage.Slice(RoundPolynomialScalarIndex(layer, hand, round, point) * ScalarSize, ScalarSize);


    /// <summary>Returns the canonical scalar bytes of claim <paramref name="claim"/> (<c>wc[claim]</c>) of <paramref name="layer"/>.</summary>
    public ReadOnlySpan<byte> Claim(int layer, int claim) =>
        Storage.Slice(ClaimScalarIndex(layer, claim) * ScalarSize, ScalarSize);


    /// <summary>Writes <paramref name="value"/> into round polynomial point <paramref name="point"/> for <paramref name="hand"/>, <paramref name="round"/> of <paramref name="layer"/>.</summary>
    public void SetRoundPolynomialPoint(int layer, int hand, int round, int point, ReadOnlySpan<byte> value) =>
        value.CopyTo(Storage.Slice(RoundPolynomialScalarIndex(layer, hand, round, point) * ScalarSize, ScalarSize));


    /// <summary>Writes <paramref name="value"/> into claim <paramref name="claim"/> (<c>wc[claim]</c>) of <paramref name="layer"/>.</summary>
    public void SetClaim(int layer, int claim, ReadOnlySpan<byte> value) =>
        value.CopyTo(Storage.Slice(ClaimScalarIndex(layer, claim) * ScalarSize, ScalarSize));


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = buffer;
        if(local is not null)
        {
            buffer = null;
            local.Memory.Span[..(totalScalars * ScalarSize)].Clear();
            local.Dispose();
        }
    }


    private Span<byte> Storage =>
        (buffer ?? throw new ObjectDisposedException(nameof(LongfellowSumcheckProof))).Memory.Span[..(totalScalars * ScalarSize)];


    //A layer holds 2 hands * logw rounds * 3 points round-polynomial scalars, then 2 claim scalars.
    private static int LayerScalars(int handRounds) => (HandCount * handRounds * RoundPolynomialPoints) + ClaimCount;


    private int RoundPolynomialScalarIndex(int layer, int hand, int round, int point) =>
        layerOffset[layer] + (((hand * handRoundsPerLayer[layer]) + round) * RoundPolynomialPoints) + point;


    private int ClaimScalarIndex(int layer, int claim) =>
        layerOffset[layer] + (HandCount * handRoundsPerLayer[layer] * RoundPolynomialPoints) + claim;
}
