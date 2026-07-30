using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The public statement a JWT statement verify checks: the issuer's out-of-band public key and the set of
/// attributes the prover must disclose from the decoded payload, framed against a pinned block-capacity
/// specification.
/// </summary>
/// <remarks>
/// The issuer key coordinates are canonical big-endian 32-byte affine coordinates and the verifier's
/// out-of-band trust anchor, never derived from the token. Duplicate attribute identifiers are allowed: each
/// <see cref="LongfellowJwtAttribute"/> is an independent pattern, located separately in the decoded payload,
/// exactly as the reference treats them.
/// </remarks>
public sealed class LongfellowJwtStatement
{
    private LongfellowJwtStatement(
        ReadOnlyMemory<byte> issuerKeyX,
        ReadOnlyMemory<byte> issuerKeyY,
        IReadOnlyList<LongfellowJwtAttribute> attributes,
        LongfellowJwtZkSpec spec)
    {
        IssuerKeyX = issuerKeyX;
        IssuerKeyY = issuerKeyY;
        Attributes = attributes;
        Spec = spec;
    }


    /// <summary>The issuer public key's x coordinate, canonical big-endian; the verifier's out-of-band trust anchor, never derived from the token.</summary>
    public ReadOnlyMemory<byte> IssuerKeyX { get; }

    /// <summary>The issuer public key's y coordinate, canonical big-endian; the verifier's out-of-band trust anchor, never derived from the token.</summary>
    public ReadOnlyMemory<byte> IssuerKeyY { get; }

    /// <summary>The attributes the verifier requires disclosed. Duplicate identifiers are allowed: each entry is an independent pattern, located separately.</summary>
    public IReadOnlyList<LongfellowJwtAttribute> Attributes { get; }

    /// <summary>The block-capacity specification the statement is compiled against.</summary>
    public LongfellowJwtZkSpec Spec { get; }


    /// <summary>
    /// Validates and wraps the caller-assembled statement.
    /// </summary>
    /// <param name="issuerKeyX">The issuer public key's x coordinate; exactly <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="issuerKeyY">The issuer public key's y coordinate; exactly <see cref="Scalar.SizeBytes"/> bytes.</param>
    /// <param name="attributes">The attributes the verifier requires disclosed; at least one entry, none <see langword="null"/>.</param>
    /// <param name="spec">The block-capacity specification the statement is compiled against.</param>
    /// <returns>A validated statement.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="attributes"/> or <paramref name="spec"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a key coordinate is not exactly <see cref="Scalar.SizeBytes"/> bytes, when <paramref name="attributes"/> is empty, or when a list entry is <see langword="null"/>.</exception>
    public static LongfellowJwtStatement Create(
        ReadOnlyMemory<byte> issuerKeyX,
        ReadOnlyMemory<byte> issuerKeyY,
        IReadOnlyList<LongfellowJwtAttribute> attributes,
        LongfellowJwtZkSpec spec)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        ArgumentNullException.ThrowIfNull(spec);

        if(issuerKeyX.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"The issuer key x coordinate is exactly {Scalar.SizeBytes} bytes; received {issuerKeyX.Length}.", nameof(issuerKeyX));
        }

        if(issuerKeyY.Length != Scalar.SizeBytes)
        {
            throw new ArgumentException($"The issuer key y coordinate is exactly {Scalar.SizeBytes} bytes; received {issuerKeyY.Length}.", nameof(issuerKeyY));
        }

        if(attributes.Count == 0)
        {
            throw new ArgumentException("A statement discloses at least one attribute; a zero-attribute compile is an un-pinned shape.", nameof(attributes));
        }

        for(int i = 0; i < attributes.Count; i++)
        {
            if(attributes[i] is null)
            {
                throw new ArgumentException($"Attribute entry {i} is null.", nameof(attributes));
            }
        }

        return new LongfellowJwtStatement(issuerKeyX, issuerKeyY, attributes, spec);
    }
}
