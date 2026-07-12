using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The public statement a dual-field mdoc verify checks: the two field public-input TEMPLATES the caller
/// assembles from the disclosed attributes, the issuer public key and the device-authentication hash. The MAC
/// and shared-key public inputs are spliced in by the verifier from the proof envelope, so they are not part
/// of the template.
/// </summary>
/// <remarks>
/// The hash template is the <c>[constant-one, attribute bits, now bits]</c> prefix in the GF(2^128) wire
/// framing (one 16-byte little-endian element per slot); the signature template is <c>[constant-one,
/// public-key x, public-key y, e2]</c> as canonical big-endian field elements (the facade frames them into the
/// Montgomery wire domain). The <c>e2</c> device-authentication value is computed caller-side; the library
/// performs no CBOR or COSE parsing. This is a validated view over caller-owned buffers.
/// </remarks>
public sealed class LongfellowMdocStatement
{
    //One canonical big-endian field element per 32-byte slot.
    private const int ScalarSizeBytes = 32;

    /// <summary>The little-endian wire width of one GF(2^128) hash template element.</summary>
    public const int HashTemplateElementBytes = 16;

    /// <summary>The element count of the signature public-input template: constant-one, public-key x, public-key y, e2.</summary>
    public const int SignatureTemplateElementCount = 4;


    private LongfellowMdocStatement(LongfellowMdocZkSpec spec, ReadOnlyMemory<byte> hashTemplate, ReadOnlyMemory<byte> signatureTemplateCanonical)
    {
        Spec = spec;
        HashTemplate = hashTemplate;
        SignatureTemplateCanonical = signatureTemplateCanonical;
    }


    /// <summary>The proof specification the templates were assembled for; the verify path is parameterized by it.</summary>
    public LongfellowMdocZkSpec Spec { get; }

    /// <summary>The GF(2^128) hash public-input template, <see cref="LongfellowMdocZkSpec.HashTemplateElementCount"/> · 16 little-endian bytes.</summary>
    public ReadOnlyMemory<byte> HashTemplate { get; }

    /// <summary>The canonical big-endian signature public-input template, <see cref="SignatureTemplateElementCount"/> · 32 bytes.</summary>
    public ReadOnlyMemory<byte> SignatureTemplateCanonical { get; }


    /// <summary>
    /// Validates and wraps the caller-assembled public-input templates.
    /// </summary>
    /// <param name="spec">The proof specification the templates are assembled for.</param>
    /// <param name="hashTemplate">The hash template; <see cref="LongfellowMdocZkSpec.HashTemplateElementCount"/> · <see cref="HashTemplateElementBytes"/> bytes.</param>
    /// <param name="signatureTemplateCanonical">The canonical big-endian signature template; <see cref="SignatureTemplateElementCount"/> · 32 bytes.</param>
    /// <returns>A validated statement view over the supplied buffers.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="spec"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a template length is invalid.</exception>
    public static LongfellowMdocStatement FromComponents(
        LongfellowMdocZkSpec spec,
        ReadOnlyMemory<byte> hashTemplate,
        ReadOnlyMemory<byte> signatureTemplateCanonical)
    {
        ArgumentNullException.ThrowIfNull(spec);

        int expectedHash = spec.HashTemplateElementCount * HashTemplateElementBytes;
        if(hashTemplate.Length != expectedHash)
        {
            throw new ArgumentException($"The hash template must be {expectedHash} bytes; received {hashTemplate.Length}.", nameof(hashTemplate));
        }

        int expectedSignature = SignatureTemplateElementCount * ScalarSizeBytes;
        if(signatureTemplateCanonical.Length != expectedSignature)
        {
            throw new ArgumentException($"The signature template must be {expectedSignature} bytes; received {signatureTemplateCanonical.Length}.", nameof(signatureTemplateCanonical));
        }

        return new LongfellowMdocStatement(spec, hashTemplate, signatureTemplateCanonical);
    }
}
