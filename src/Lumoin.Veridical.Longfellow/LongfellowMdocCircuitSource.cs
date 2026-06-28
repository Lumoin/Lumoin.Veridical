using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The circuit-definition seam: the raw concatenated dual-field circuit bytes — the P-256 signature circuit
/// followed by the GF(2^128) hash circuit — the facade parses to recover the two circuits. The caller
/// provides the bytes; in phase 0 that is the reference circuit definition decompressed from the producer's
/// artifact.
/// </summary>
/// <remarks>
/// The facade re-parses the circuits and rebuilds the field bundles per call. Caching the parsed circuits and
/// the derived bundles across calls is a later performance refinement behind this seam, not a correctness
/// concern.
/// </remarks>
public sealed class LongfellowMdocCircuitSource
{
    private LongfellowMdocCircuitSource(ReadOnlyMemory<byte> rawCircuitBytes)
    {
        RawCircuitBytes = rawCircuitBytes;
    }


    /// <summary>The concatenated circuit-definition bytes: the signature circuit then the hash circuit.</summary>
    public ReadOnlyMemory<byte> RawCircuitBytes { get; }


    /// <summary>
    /// Wraps caller-supplied concatenated circuit-definition bytes.
    /// </summary>
    /// <param name="rawCircuitBytes">The signature-then-hash circuit-definition stream.</param>
    /// <returns>A circuit source over the supplied bytes.</returns>
    /// <exception cref="ArgumentException">When <paramref name="rawCircuitBytes"/> is empty.</exception>
    public static LongfellowMdocCircuitSource FromRawBytes(ReadOnlyMemory<byte> rawCircuitBytes)
    {
        if(rawCircuitBytes.IsEmpty)
        {
            throw new ArgumentException("The circuit-definition bytes must be non-empty.", nameof(rawCircuitBytes));
        }

        return new LongfellowMdocCircuitSource(rawCircuitBytes);
    }
}
