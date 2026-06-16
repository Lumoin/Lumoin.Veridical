using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant byte serialization of the zk sumcheck segment, a faithful port of
/// google/longfellow-zk's <c>ZkProof&lt;Field&gt;::write_sc_proof</c> / <c>read_sc_proof</c>
/// (<c>lib/zk/zk_proof.h</c>) — the middle segment of the full <c>ZkProof</c> envelope
/// <c>com ‖ sc ‖ com_proof</c>. The commitment root (<c>write_com</c>) is the caller's 32-byte digest and
/// the Ligero proof (<c>write_com_proof</c>) is <see cref="LongfellowLigeroProofSerializer"/>; this
/// serializer is the sumcheck transcript between them.
/// </summary>
/// <remarks>
/// <para>
/// The byte layout, per layer, gated on <c>logc == 0</c> (the reference asserts no copies):
/// </para>
/// <list type="number">
///   <item><description>For each of <c>logw</c> rounds, for each point <c>k ∈ {0, 2}</c> (the <c>k != 1</c> optimization — <c>p(1)</c> is implied by <c>claim = p(0) + p(1)</c> and not sent): write the left hand's <c>hp[0][round].t_[k]</c> then the right hand's <c>hp[1][round].t_[k]</c>. The loop is point-outer, hand-inner.</description></item>
///   <item><description>The two next-layer claims <c>wc[0]</c>, <c>wc[1]</c>.</description></item>
/// </list>
/// <para>
/// Each element is 16 little-endian <c>to_bytes_field</c> bytes (the low 128 bits of the GF(2^128)
/// element, least-significant byte first), reversed into / out of the codebase's 32-byte big-endian
/// canonical scalar. A layer is exactly <c>(logw·(3−1)·2 + 2)·16</c> bytes; <c>read_sc_proof</c> derives
/// this same needed-byte count per layer and returns failure on underflow. The unsent <c>p(1)</c> slots
/// (<c>t_[1]</c>) are left zero on read — the verifier reconstructs them from the running claim.
/// </para>
/// <para>
/// The reader is parse-safe: it returns <see langword="null"/> on any underflow (mirroring the
/// reference's <c>false</c>), and the partially built proof is disposed so no pooled buffer leaks.
/// </para>
/// </remarks>
internal static class LongfellowSumcheckProofSerializer
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Returns the exact serialized byte size of a sumcheck proof for <paramref name="circuit"/>, the sum
    /// over layers of <c>(logw·(3−1)·2 + 2)·ElementBytes</c>. The size depends only on the circuit shape
    /// and the element width, never on the values, so it equals both the writer's output length and the
    /// reader's consumed length.
    /// </summary>
    /// <param name="circuit">The circuit the proof was produced for; must have <c>logc == 0</c>.</param>
    /// <param name="profile">The field profile; supplies the on-wire element width (16 for GF(2^128), 32 for Fp256).</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies (<c>logc != 0</c>).</exception>
    public static int SerializedSize(LongfellowSumcheckCircuit circuit, LongfellowFieldProfile profile)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(profile);
        RequireNoCopies(circuit);

        int size = 0;
        foreach(LongfellowSumcheckLayer layer in circuit.Layers)
        {
            size += LayerByteSize(layer.HandRounds, profile.ElementBytes);
        }

        return size;
    }


    /// <summary>
    /// Writes <paramref name="proof"/> into <paramref name="destination"/> in the reference's
    /// <c>write_sc_proof</c> byte layout and returns the number of bytes written.
    /// </summary>
    /// <param name="circuit">The circuit shape driving the layout; must have <c>logc == 0</c>.</param>
    /// <param name="proof">The proof to serialize.</param>
    /// <param name="profile">The field profile; supplies the on-wire element width and the <c>to_bytes_field</c> framing.</param>
    /// <param name="destination">The buffer to write into; at least <see cref="SerializedSize"/> bytes.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies or <paramref name="destination"/> is too small.</exception>
    public static int Write(LongfellowSumcheckCircuit circuit, LongfellowSumcheckProof proof, LongfellowFieldProfile profile, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(profile);
        RequireNoCopies(circuit);

        int elementBytes = profile.ElementBytes;
        int required = SerializedSize(circuit, profile);
        if(destination.Length < required)
        {
            throw new ArgumentException($"The destination holds {destination.Length} bytes; the sc proof needs {required}.", nameof(destination));
        }

        int offset = 0;
        for(int layer = 0; layer < circuit.LayerCount; layer++)
        {
            int handRounds = circuit.Layers[layer].HandRounds;
            for(int round = 0; round < handRounds; round++)
            {
                //Point-outer (k ∈ {0, 2}), hand-inner (left then right), the reference's loop order.
                profile.ToBytesField(proof.RoundPolynomialPoint(layer, 0, round, 0), destination.Slice(offset, elementBytes));
                offset += elementBytes;
                profile.ToBytesField(proof.RoundPolynomialPoint(layer, 1, round, 0), destination.Slice(offset, elementBytes));
                offset += elementBytes;
                profile.ToBytesField(proof.RoundPolynomialPoint(layer, 0, round, 2), destination.Slice(offset, elementBytes));
                offset += elementBytes;
                profile.ToBytesField(proof.RoundPolynomialPoint(layer, 1, round, 2), destination.Slice(offset, elementBytes));
                offset += elementBytes;
            }

            profile.ToBytesField(proof.Claim(layer, 0), destination.Slice(offset, elementBytes));
            offset += elementBytes;
            profile.ToBytesField(proof.Claim(layer, 1), destination.Slice(offset, elementBytes));
            offset += elementBytes;
        }

        return offset;
    }


    /// <summary>
    /// Reads a <see cref="LongfellowSumcheckProof"/> out of <paramref name="source"/> in the reference's
    /// <c>read_sc_proof</c> byte layout. The shapes come from <paramref name="circuit"/>; the bytes supply
    /// the values. The unsent <c>p(1)</c> points are left zero. Returns the parsed proof on success, or
    /// <see langword="null"/> on any underflow — mirroring the reference's <c>false</c> return.
    /// </summary>
    /// <param name="circuit">The circuit the proof was produced for; must have <c>logc == 0</c>.</param>
    /// <param name="profile">The field profile; supplies the on-wire element width and the <c>of_bytes_field</c> framing.</param>
    /// <param name="pool">The pool the parsed proof's buffer rents from.</param>
    /// <param name="source">The serialized bytes.</param>
    /// <param name="bytesRead">The number of bytes consumed on success; <c>0</c> on failure.</param>
    /// <returns>The parsed proof, or <see langword="null"/> on malformed input. The caller owns and disposes a non-null result.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies (<c>logc != 0</c>).</exception>
    public static LongfellowSumcheckProof? Read(
        LongfellowSumcheckCircuit circuit,
        LongfellowFieldProfile profile,
        BaseMemoryPool pool,
        ReadOnlySpan<byte> source,
        out int bytesRead)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(pool);
        RequireNoCopies(circuit);

        bytesRead = 0;
        int elementBytes = profile.ElementBytes;

        LongfellowSumcheckProof? proof = null;
        try
        {
            proof = new LongfellowSumcheckProof(circuit, pool);

            Span<byte> scalar = stackalloc byte[ScalarSize];
            int offset = 0;
            for(int layer = 0; layer < circuit.LayerCount; layer++)
            {
                int handRounds = circuit.Layers[layer].HandRounds;

                //read_sc_proof's per-layer guard: needed = (logw*(3-1)*2 + 2)*kBytes, checked up front.
                int needed = LayerByteSize(handRounds, elementBytes);
                if(source.Length - offset < needed)
                {
                    return null;
                }

                for(int round = 0; round < handRounds; round++)
                {
                    //Wire order is point-outer, hand-inner; the unsent p(1) (point 1) stays zero from
                    //the proof's cleared buffer. An element the field rejects fails the parse, the
                    //reference's read_sc_proof of_bytes_field contract.
                    for(int point = 0; point < LongfellowSumcheckProof.RoundPolynomialPoints; point += 2)
                    {
                        for(int hand = 0; hand < LongfellowSumcheckProof.HandCount; hand++)
                        {
                            if(!profile.TryFromBytesField(source.Slice(offset, elementBytes), scalar))
                            {
                                return null;
                            }

                            proof.SetRoundPolynomialPoint(layer, hand, round, point, scalar);
                            offset += elementBytes;
                        }
                    }
                }

                for(int claim = 0; claim < LongfellowSumcheckProof.ClaimCount; claim++)
                {
                    if(!profile.TryFromBytesField(source.Slice(offset, elementBytes), scalar))
                    {
                        return null;
                    }

                    proof.SetClaim(layer, claim, scalar);
                    offset += elementBytes;
                }
            }

            bytesRead = offset;
            LongfellowSumcheckProof parsed = proof;
            proof = null;

            return parsed;
        }
        finally
        {
            //On every non-success path (an underflow return null, or an exception) proof is still owned
            //here and must be released; on success it was handed to the caller and nulled above.
            proof?.Dispose();
        }
    }


    //read_sc_proof's per-layer needed-bytes formula: (logw*(3-1)*2 + 2)*kBytes.
    private static int LayerByteSize(int handRounds, int elementBytes) =>
        ((handRounds * (LongfellowSumcheckProof.RoundPolynomialPoints - 1) * LongfellowSumcheckProof.HandCount) + LongfellowSumcheckProof.ClaimCount) * elementBytes;


    private static void RequireNoCopies(LongfellowSumcheckCircuit circuit)
    {
        if(circuit.CopyRounds != 0)
        {
            throw new ArgumentException($"write_sc_proof / read_sc_proof require logc == 0; the circuit has logc = {circuit.CopyRounds}.", nameof(circuit));
        }
    }
}
