using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The proof pad the ZK prover commits and subtracts from the sumcheck transcript, a faithful port of the
/// <c>logc == 0</c> subset of google/longfellow-zk's <c>ZkProver::fill_pad</c> (<c>lib/zk/zk_prover.h</c>)
/// over the <c>Proof&lt;Field&gt;</c> pad layout. Per layer it holds, per round per hand, the two
/// transmitted round-polynomial pads <c>dP(0)</c>, <c>dP(2)</c> (the <c>p(1)</c> point is not padded),
/// then the two wire-claim pads <c>dWC[0]</c>, <c>dWC[1]</c> and their product <c>dWC[0]·dWC[1]</c>.
/// </summary>
/// <remarks>
/// <para>
/// The pad encrypts the sumcheck transcript: the prover subtracts each pad value from the computed
/// quantity before writing it to the proof, and commits the pad so the Ligero proof can verify the
/// padded transcript satisfies the sumcheck verifier. <see cref="Fill"/> draws the pad from the random
/// source in the reference's exact order — per layer, for each round for each hand the two drawn poly
/// pads (the <c>p(1)</c> slot is the field zero, not drawn), then the two drawn claim pads, then the
/// computed product — and lays the drawn values out as the pad witness exactly as <c>fill_pad</c>'s
/// <c>witness_.push_back</c> sequence does. <see cref="CopyWitnessTo"/> emits that witness segment for
/// the commitment.
/// </para>
/// <para>
/// Each draw is one full-field element: <see cref="LongfellowFieldProfile.ElementBytes"/> raw bytes from
/// the source mapped through <c>of_bytes_field</c> (little-endian to canonical), matching
/// <c>rng.elt(F)</c>. The pad witness count per layer is <c>4·logw + 3</c> (the without-overlap
/// pad-layout size), of which <c>4·logw + 2</c> are drawn and one (the product) is computed. The pad
/// backing buffer carries randomness and is cleared on disposal.
/// </para>
/// </remarks>
internal sealed class LongfellowProofPad: IDisposable
{
    private const int ScalarSize = Scalar.SizeBytes;

    //A round polynomial is degree-3 with three points; only points 0 and 2 are padded.
    private const int RoundPolynomialPoints = LongfellowSumcheckProof.RoundPolynomialPoints;
    private const int HandCount = LongfellowSumcheckProof.HandCount;
    private const int ClaimCount = LongfellowSumcheckProof.ClaimCount;

    private readonly int[] handRoundsPerLayer;
    private readonly int[] layerOffset;
    private readonly int totalScalars;
    private readonly int witnessScalars;

    private IMemoryOwner<byte>? buffer;


    private LongfellowProofPad(int[] handRoundsPerLayer, int[] layerOffset, int totalScalars, int witnessScalars, IMemoryOwner<byte> buffer)
    {
        this.handRoundsPerLayer = handRoundsPerLayer;
        this.layerOffset = layerOffset;
        this.totalScalars = totalScalars;
        this.witnessScalars = witnessScalars;
        this.buffer = buffer;
    }


    /// <summary>The number of pad witness elements (the reference's <c>pad_size(c)</c>).</summary>
    public int WitnessScalarCount => witnessScalars;


    /// <summary>
    /// Draws and lays out the proof pad for <paramref name="circuit"/> from <paramref name="random"/>, in
    /// the reference's <c>fill_pad</c> order, computing each layer's claim-pad product. The result owns its
    /// pad storage; the caller disposes it.
    /// </summary>
    /// <param name="circuit">The circuit shape; must have <c>logc == 0</c>.</param>
    /// <param name="random">The raw-byte entropy source, consumed in the reference's fixed order.</param>
    /// <param name="profile">The field profile: the element width each draw consumes and the <c>of_bytes_field</c> mapping.</param>
    /// <param name="multiply">Field multiplication (for the claim-pad product).</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="pool">The pool the pad storage rents from.</param>
    /// <returns>The filled pad; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies.</exception>
    public static LongfellowProofPad Fill(
        LongfellowSumcheckCircuit circuit,
        LongfellowRandomByteSource random,
        LongfellowFieldProfile profile,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(pool);

        if(circuit.CopyRounds != 0)
        {
            throw new ArgumentException($"The proof pad layout requires logc == 0; the circuit has logc = {circuit.CopyRounds}.", nameof(circuit));
        }

        int layerCount = circuit.LayerCount;
        int[] handRoundsPerLayer = new int[layerCount];
        int[] layerOffset = new int[layerCount];

        int offset = 0;
        int witnessScalars = 0;
        for(int layer = 0; layer < layerCount; layer++)
        {
            int handRounds = circuit.Layers[layer].HandRounds;
            handRoundsPerLayer[layer] = handRounds;
            layerOffset[layer] = offset;
            offset += LayerScalars(handRounds);
            witnessScalars += LayerScalars(handRounds);
        }

        int totalScalars = offset;
        IMemoryOwner<byte> buffer = pool.Rent(Math.Max(totalScalars, 1) * ScalarSize);
        bool transferred = false;
        try
        {
            Span<byte> pad = buffer.Memory.Span[..(Math.Max(totalScalars, 1) * ScalarSize)];
            pad.Clear();

            //Draw the pad in fill_pad order: per layer, per round per hand the two poly pads, then the two
            //claim pads, then the computed product. The drawn values are laid out at the without-overlap
            //pad indices, which is exactly the witness-append order.
            for(int layer = 0; layer < layerCount; layer++)
            {
                int handRounds = handRoundsPerLayer[layer];
                var layout = new LongfellowZkPadLayout(handRounds);
                int baseOffset = layerOffset[layer];

                for(int round = 0; round < handRounds; round++)
                {
                    for(int hand = 0; hand < HandCount; hand++)
                    {
                        int r = (2 * round) + hand;
                        DrawElement(random, profile, pad.Slice((baseOffset + LongfellowZkPadLayout.PolyPadWithoutOverlap(r, 0)) * ScalarSize, ScalarSize));
                        DrawElement(random, profile, pad.Slice((baseOffset + LongfellowZkPadLayout.PolyPadWithoutOverlap(r, 2)) * ScalarSize, ScalarSize));
                    }
                }

                //wc[0], wc[1] drawn; wc[0]·wc[1] computed.
                Span<byte> wc0 = pad.Slice((baseOffset + layout.ClaimPad(0)) * ScalarSize, ScalarSize);
                Span<byte> wc1 = pad.Slice((baseOffset + layout.ClaimPad(1)) * ScalarSize, ScalarSize);
                Span<byte> product = pad.Slice((baseOffset + layout.ClaimPad(2)) * ScalarSize, ScalarSize);
                DrawElement(random, profile, wc0);
                DrawElement(random, profile, wc1);
                multiply(wc0, wc1, product, curve);
            }

            //An identically-zero pad encrypts nothing: the padded transcript is
            //the cleartext transcript and the proof still verifies, so the
            //zero-knowledge property is silently void. A healthy byte source
            //cannot produce an all-zero pad (every drawn element would have to
            //be zero), so this only ever signals a broken entropy source —
            //reject at generation, the one place the pad is visible.
            if(totalScalars > 0 && pad.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new InvalidOperationException(
                    "The drawn proof pad is identically zero. A zero pad voids the zero-knowledge (hiding) property "
                    + "while the proof remains sound, and can only come from a broken entropy source; check the "
                    + "LongfellowRandomByteSource wiring supplied to Fill.");
            }

            var result = new LongfellowProofPad(handRoundsPerLayer, layerOffset, totalScalars, witnessScalars, buffer);
            transferred = true;

            return result;
        }
        finally
        {
            if(!transferred)
            {
                buffer.Memory.Span.Clear();
                buffer.Dispose();
            }
        }
    }


    /// <summary>Returns the pad value of round polynomial point <paramref name="point"/> for <paramref name="hand"/>, <paramref name="round"/> of <paramref name="layer"/>.</summary>
    public ReadOnlySpan<byte> PolyPad(int layer, int hand, int round, int point)
    {
        int r = (2 * round) + hand;

        return Storage.Slice((layerOffset[layer] + LongfellowZkPadLayout.PolyPadWithoutOverlap(r, point)) * ScalarSize, ScalarSize);
    }


    /// <summary>Returns the pad value of claim pad entry <paramref name="n"/> of <paramref name="layer"/>.</summary>
    public ReadOnlySpan<byte> ClaimPad(int layer, int n)
    {
        var layout = new LongfellowZkPadLayout(handRoundsPerLayer[layer]);

        return Storage.Slice((layerOffset[layer] + layout.ClaimPad(n)) * ScalarSize, ScalarSize);
    }


    /// <summary>
    /// Copies the pad witness segment (the drawn poly/claim pads and the computed products, in fill_pad
    /// order) into <paramref name="destination"/>. The without-overlap pad layout is exactly the
    /// witness-append order, so the contiguous pad storage is the witness segment.
    /// </summary>
    /// <param name="destination">Receives <see cref="WitnessScalarCount"/> · 32 canonical bytes.</param>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is the wrong length.</exception>
    public void CopyWitnessTo(Span<byte> destination)
    {
        if(destination.Length != witnessScalars * ScalarSize)
        {
            throw new ArgumentException($"Expected {witnessScalars * ScalarSize} pad-witness bytes; received {destination.Length}.", nameof(destination));
        }

        Storage[..(witnessScalars * ScalarSize)].CopyTo(destination);
    }


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
        (buffer ?? throw new ObjectDisposedException(nameof(LongfellowProofPad))).Memory.Span[..(Math.Max(totalScalars, 1) * ScalarSize)];


    //The without-overlap layer size: 4·logw poly pads plus 3 claim pads.
    private static int LayerScalars(int handRounds) => (HandCount * handRounds * (RoundPolynomialPoints - 1)) + ClaimCount + 1;


    //Draws one full-field element through the field's sample mask-then-reject loop, the reference's
    //rng.elt(F) (random.h:39-41). GF(2^128) is one 16-byte draw (never rejects); the Fp256 profile
    //redraws a fresh 32-byte block until one is below the modulus.
    private static void DrawElement(LongfellowRandomByteSource random, LongfellowFieldProfile profile, Span<byte> destination)
    {
        profile.SampleElement(random, destination);
    }
}
