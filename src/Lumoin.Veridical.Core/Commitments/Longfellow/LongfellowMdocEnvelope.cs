using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The dual-field mdoc proof envelope, a faithful port of the byte layout
/// google/longfellow-zk's <c>run_mdoc_prover</c> serializes and <c>run_mdoc_verifier</c> reads
/// (<c>lib/circuits/mdoc/mdoc_zk.cc</c>): <c>[6 mac values] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>. The six
/// MAC values are <c>6 · f_128::kBytes = 96</c> bytes (each a 16-byte little-endian GF(2^128) element); the
/// hash proof is the GF(2^128) hash circuit's full <c>ZkProof</c> envelope (<c>com ‖ sc ‖ com_proof</c>),
/// and the signature proof is the P-256 base-field signature circuit's full <c>ZkProof</c> envelope.
/// </summary>
/// <remarks>
/// <para>
/// The docType is NOT in these bytes — it is a verifier argument that feeds the signature circuit's <c>e2</c>
/// public input through <c>compute_transcript_hash</c>. The reference reads the envelope sequentially from a
/// <c>ReadBuffer</c>: 6 MACs, then <c>pr_hash.read(rb)</c>, then <c>pr_sig.read(rb)</c>, requiring
/// <c>rb.remaining() == 0</c> at the end.
/// </para>
/// <para>
/// This reader splits the envelope by length-probing each proof. The hash proof's length is its commitment
/// digest (32) plus its sumcheck segment (derived from the hash circuit shape) plus the bytes its Ligero
/// <c>com_proof</c> consumes (run-length encoded, so data-dependent). The signature proof is the remaining
/// bytes. The mac region and the hash-proof split are exercised over the GF(2^128) serializers; isolating the
/// signature-proof slice's internal structure additionally needs the width-32 sumcheck/Ligero serializers.
/// </para>
/// </remarks>
internal static class LongfellowMdocEnvelope
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's f_128::kBytes: each MAC value is a 16-byte little-endian GF(2^128) element.
    private const int MacElementBytes = 16;

    /// <summary>The number of MAC values prefixing the envelope (the reference's <c>6</c>).</summary>
    public const int MacCount = 6;

    /// <summary>The total byte length of the MAC prefix (<c>6 · 16 = 96</c>).</summary>
    public const int MacRegionBytes = MacCount * MacElementBytes;

    //The reference's Digest::kLength: the ZkProof commitment root is 32 bytes (write_com).
    private const int CommitmentRootBytes = 32;


    /// <summary>
    /// Splits an mdoc proof envelope into the MAC region, the hash <c>ZkProof</c> bytes and the signature
    /// <c>ZkProof</c> bytes, the reference's <c>run_mdoc_verifier</c> read order. The hash proof length is
    /// probed via the GF(2^128) serializers; the signature proof is the remainder.
    /// </summary>
    /// <param name="envelope">The full envelope <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>.</param>
    /// <param name="hashCircuit">The GF(2^128) hash circuit (drives the hash proof's sumcheck-segment length).</param>
    /// <param name="hashParameters">The hash circuit's Ligero parameters (drive the hash proof's <c>com_proof</c> read).</param>
    /// <param name="hashSubFieldBytes">The hash circuit's subfield byte size (2 for GF(2^16)).</param>
    /// <param name="hashFft">The LCH14 additive-FFT engine for the hash proof's <c>com_proof</c> read.</param>
    /// <param name="pool">Pool the transient parse buffers rent from.</param>
    /// <param name="layout">On success, the offsets and lengths of the three regions.</param>
    /// <returns><see langword="true"/> when the envelope is well-formed through the hash proof; <see langword="false"/> on any underflow or malformed hash proof.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    public static bool TrySplit(
        ReadOnlySpan<byte> envelope,
        LongfellowSumcheckCircuit hashCircuit,
        LongfellowLigeroParameters hashParameters,
        int hashSubFieldBytes,
        Lch14AdditiveFft hashFft,
        BaseMemoryPool pool,
        out LongfellowMdocEnvelopeLayout layout)
    {
        ArgumentNullException.ThrowIfNull(hashCircuit);
        ArgumentNullException.ThrowIfNull(hashParameters);
        ArgumentNullException.ThrowIfNull(hashFft);
        ArgumentNullException.ThrowIfNull(pool);

        layout = default;

        //The GF(2^128) field profile of the hash circuit, derived from its additive-FFT engine.
        LongfellowFieldProfile hashProfile = LongfellowGf2k128Encoding.CreateProfile(hashFft);

        if(envelope.Length < MacRegionBytes)
        {
            return false;
        }

        ReadOnlySpan<byte> afterMacs = envelope[MacRegionBytes..];

        //The hash ZkProof: com (32) || sc (shape-derived) || com_proof (data-dependent, length probed).
        if(afterMacs.Length < CommitmentRootBytes)
        {
            return false;
        }

        int scSize = LongfellowSumcheckProofSerializer.SerializedSize(hashCircuit, hashProfile);
        if(afterMacs.Length < CommitmentRootBytes + scSize)
        {
            return false;
        }

        ReadOnlySpan<byte> hashComProof = afterMacs[(CommitmentRootBytes + scSize)..];
        using LongfellowLigeroProof? hashLigero = LongfellowLigeroProofSerializer.Read(
            hashParameters, hashSubFieldBytes, hashProfile, hashFft, pool, hashComProof, out int hashComProofBytes);
        if(hashLigero is null)
        {
            return false;
        }

        int hashProofBytes = CommitmentRootBytes + scSize + hashComProofBytes;
        if(afterMacs.Length < hashProofBytes)
        {
            return false;
        }

        int sigProofOffset = MacRegionBytes + hashProofBytes;
        layout = new LongfellowMdocEnvelopeLayout(
            MacRegionOffset: 0,
            MacRegionBytes: MacRegionBytes,
            HashProofOffset: MacRegionBytes,
            HashProofBytes: hashProofBytes,
            SigProofOffset: sigProofOffset,
            SigProofBytes: envelope.Length - sigProofOffset);

        return layout.SigProofBytes >= 0;
    }


    /// <summary>
    /// Copies the six MAC values from <paramref name="envelope"/> into <paramref name="macs"/> as canonical
    /// 32-byte big-endian scalars (the reference's <c>Fs.of_bytes_field</c> over the 16-byte little-endian
    /// wire framing).
    /// </summary>
    /// <param name="envelope">The full envelope; at least <see cref="MacRegionBytes"/> bytes.</param>
    /// <param name="macs">Receives <see cref="MacCount"/> canonical scalars (<see cref="MacCount"/> · 32 bytes).</param>
    /// <exception cref="ArgumentException">When a span is the wrong length.</exception>
    public static void ReadMacs(ReadOnlySpan<byte> envelope, Span<byte> macs)
    {
        if(envelope.Length < MacRegionBytes)
        {
            throw new ArgumentException($"The envelope must be at least {MacRegionBytes} bytes to hold the MACs; received {envelope.Length}.", nameof(envelope));
        }

        if(macs.Length != MacCount * ScalarSize)
        {
            throw new ArgumentException($"The macs span must be {MacCount * ScalarSize} bytes; received {macs.Length}.", nameof(macs));
        }

        macs.Clear();
        for(int i = 0; i < MacCount; i++)
        {
            ReadOnlySpan<byte> littleEndian = envelope.Slice(i * MacElementBytes, MacElementBytes);
            Span<byte> canonical = macs.Slice(i * ScalarSize, ScalarSize);
            for(int b = 0; b < MacElementBytes; b++)
            {
                canonical[ScalarSize - 1 - b] = littleEndian[b];
            }
        }
    }
}
