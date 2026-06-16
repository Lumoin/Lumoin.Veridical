using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The mac/av splice into the two public-input vectors, the reference's <c>fill_public_inputs</c> tail
/// (<c>lib/circuits/mdoc/mdoc_zk.cc:177-209</c>) over the <c>fill_gf2k</c> fillers
/// (<c>lib/circuits/mac/mac_reference.h:62-68</c>). The driver supplies a pre-built public-input template
/// per field (per D5 the CBOR/attribute/<c>now</c> walk and the <c>e2</c> computation are caller-side); this
/// appends the six macs and the shared key <c>a_v</c> in each field's framing and guards the spliced length
/// against the circuit's declared <c>npub_in</c>.
/// </summary>
/// <remarks>
/// On the GF(2^128) hash side each mac and <c>a_v</c> is appended as ONE 16-byte element (the
/// <c>fill_gf2k&lt;f_128, f_128&gt;</c> specialization = <c>push_back(m)</c>, NOT bit-expanded). On the Fp256
/// signature side each is appended as 128 one/zero base-field wires, the GF element's bits least-significant
/// first (the generic <c>fill_gf2k&lt;f_128, Fp256Base&gt;</c>). A spliced vector whose element count does not
/// reach the circuit's <c>npub_in</c> reproduces the reference's <c>filler.size() != npub_in</c> rejection
/// (<c>mdoc_zk.cc:686-689</c>), surfaced as a <see langword="null"/> result.
/// </remarks>
internal static class LongfellowMdocPublicInputs
{
    //f_128::kBits: a GF(2^128) element expands to 128 LSB-first base-field wires on the sig side.
    private const int MacKeyBits = 128;

    //The six per-credential macs plus the one a_v key, in both public vectors (mdoc_zk.cc:189-207).
    private const int MacCount = LongfellowMdocEnvelope.MacCount;
    private const int MacAndKeyCount = MacCount + 1;

    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Splices the GF(2^128) hash public-input vector: the template, then the six macs and <c>a_v</c> each as
    /// ONE 16-byte element. Returns <see langword="null"/> when the spliced element count does not equal
    /// <paramref name="publicInputCount"/>.
    /// </summary>
    /// <param name="profile">The GF(2^128) field profile (16-byte framing).</param>
    /// <param name="template">The hash public-input template <c>[one, attrs…, now-bits]</c>, <c>(npub_in − 7)</c> · 16 little-endian bytes.</param>
    /// <param name="macs">The six macs as canonical scalars (<see cref="LongfellowMdocEnvelope.MacCount"/> · 32 bytes).</param>
    /// <param name="av">The shared MAC key as a canonical scalar.</param>
    /// <param name="publicInputCount">The circuit's <c>npub_in</c> (the spliced element count must match).</param>
    /// <param name="pool">Pool the spliced vector rents from.</param>
    /// <returns>The spliced vector (the caller disposes it), or <see langword="null"/> on a count mismatch.</returns>
    public static IMemoryOwner<byte>? SpliceHash(
        LongfellowFieldProfile profile,
        ReadOnlySpan<byte> template,
        ReadOnlySpan<byte> macs,
        ReadOnlySpan<byte> av,
        int publicInputCount,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(pool);

        int elementBytes = profile.ElementBytes;
        if(template.Length % elementBytes != 0)
        {
            return null;
        }

        int templateElements = template.Length / elementBytes;
        if(templateElements + MacAndKeyCount != publicInputCount)
        {
            return null;
        }

        IMemoryOwner<byte> owner = pool.Rent(publicInputCount * elementBytes);
        Span<byte> pub = owner.Memory.Span[..(publicInputCount * elementBytes)];
        template.CopyTo(pub);

        int offset = template.Length;
        for(int i = 0; i < MacCount; i++)
        {
            profile.ToBytesField(macs.Slice(i * ScalarSize, ScalarSize), pub.Slice(offset, elementBytes));
            offset += elementBytes;
        }

        profile.ToBytesField(av, pub.Slice(offset, elementBytes));

        return owner;
    }


    /// <summary>
    /// Splices the Fp256 signature public-input vector: the template, then the six macs and <c>a_v</c> each as
    /// 128 one/zero base-field wires, the GF element's bits least-significant first. Returns
    /// <see langword="null"/> when the spliced element count does not equal <paramref name="publicInputCount"/>.
    /// </summary>
    /// <param name="profile">The Fp256 field profile (32-byte framing, the <c>of_scalar</c> one/zero generator).</param>
    /// <param name="template">The sig public-input template <c>[one, pkX, pkY, e2]</c>, <c>(npub_in − 7·128)</c> · 32 little-endian bytes.</param>
    /// <param name="macs">The six macs as canonical scalars (<see cref="LongfellowMdocEnvelope.MacCount"/> · 32 bytes).</param>
    /// <param name="av">The shared MAC key as a canonical scalar.</param>
    /// <param name="publicInputCount">The circuit's <c>npub_in</c> (the spliced element count must match).</param>
    /// <param name="pool">Pool the spliced vector rents from.</param>
    /// <returns>The spliced vector (the caller disposes it), or <see langword="null"/> on a count mismatch.</returns>
    public static IMemoryOwner<byte>? SpliceSig(
        LongfellowFieldProfile profile,
        ReadOnlySpan<byte> template,
        ReadOnlySpan<byte> macs,
        ReadOnlySpan<byte> av,
        int publicInputCount,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(pool);

        int elementBytes = profile.ElementBytes;
        if(template.Length % elementBytes != 0)
        {
            return null;
        }

        int templateElements = template.Length / elementBytes;
        if(templateElements + (MacAndKeyCount * MacKeyBits) != publicInputCount)
        {
            return null;
        }

        IMemoryOwner<byte> owner = pool.Rent(publicInputCount * elementBytes);
        Span<byte> pub = owner.Memory.Span[..(publicInputCount * elementBytes)];
        template.CopyTo(pub);

        //one and zero in the sig field's little-endian framing: of_scalar(1) / of_scalar(0).
        Span<byte> oneCanonical = stackalloc byte[ScalarSize];
        Span<byte> zeroCanonical = stackalloc byte[ScalarSize];
        profile.OfScalar(1, oneCanonical);
        profile.OfScalar(0, zeroCanonical);
        Span<byte> oneWire = stackalloc byte[ScalarSize];
        Span<byte> zeroWire = stackalloc byte[ScalarSize];
        profile.ToBytesField(oneCanonical, oneWire[..elementBytes]);
        profile.ToBytesField(zeroCanonical, zeroWire[..elementBytes]);

        int offset = template.Length;
        for(int i = 0; i < MacCount; i++)
        {
            ExpandBits(macs.Slice(i * ScalarSize, ScalarSize), oneWire[..elementBytes], zeroWire[..elementBytes], elementBytes, pub, ref offset);
        }

        ExpandBits(av, oneWire[..elementBytes], zeroWire[..elementBytes], elementBytes, pub, ref offset);

        oneCanonical.Clear();
        zeroCanonical.Clear();

        return owner;
    }


    //Writes the 128 base-field wires of one GF(2^128) element, least-significant bit first: bit j picks one
    //or zero. The canonical scalar is big-endian with the 16-byte element in its low bytes, so bit j sits in
    //canonical[ScalarSize - 1 - (j / 8)] at position j mod 8 (mac[j] in mac_reference.h:66).
    private static void ExpandBits(ReadOnlySpan<byte> element, ReadOnlySpan<byte> oneWire, ReadOnlySpan<byte> zeroWire, int elementBytes, Span<byte> pub, ref int offset)
    {
        for(int j = 0; j < MacKeyBits; j++)
        {
            int bit = (element[ScalarSize - 1 - (j / 8)] >> (j % 8)) & 1;
            (bit == 1 ? oneWire : zeroWire).CopyTo(pub.Slice(offset, elementBytes));
            offset += elementBytes;
        }
    }
}
