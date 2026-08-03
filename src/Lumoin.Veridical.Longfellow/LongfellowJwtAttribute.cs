using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Text;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// One attribute the verifier requires the prover to disclose, whose quoted <c>"id":"value"</c> pattern the
/// statement proves occurs in the decoded payload.
/// </summary>
public sealed class LongfellowJwtAttribute
{
    /// <summary>The identifier capacity in bytes (the reference host witness's <c>id[32]</c>).</summary>
    public const int MaxIdBytes = 32;

    /// <summary>The value capacity in bytes (the reference host witness's <c>value[64]</c>).</summary>
    public const int MaxValueBytes = 64;


    private LongfellowJwtAttribute(ReadOnlyMemory<byte> id, ReadOnlyMemory<byte> value)
    {
        Id = id;
        Value = value;
    }


    /// <summary>The attribute identifier bytes.</summary>
    public ReadOnlyMemory<byte> Id { get; }

    /// <summary>The attribute value bytes.</summary>
    public ReadOnlyMemory<byte> Value { get; }


    /// <summary>
    /// Validates and wraps the caller-supplied identifier and value bytes. An empty <paramref name="id"/> or
    /// <paramref name="value"/> is accepted: the reference accepts them, and the quoted pattern still frames
    /// them correctly.
    /// </summary>
    /// <param name="id">The identifier bytes; at most <see cref="MaxIdBytes"/> bytes.</param>
    /// <param name="value">The value bytes; at most <see cref="MaxValueBytes"/> bytes.</param>
    /// <returns>The attribute.</returns>
    /// <exception cref="ArgumentException">When either side exceeds its capacity.</exception>
    public static LongfellowJwtAttribute Create(ReadOnlyMemory<byte> id, ReadOnlyMemory<byte> value)
    {
        if(id.Length > MaxIdBytes)
        {
            throw new ArgumentException($"An attribute identifier is at most {MaxIdBytes} bytes; received {id.Length}.", nameof(id));
        }

        if(value.Length > MaxValueBytes)
        {
            throw new ArgumentException($"An attribute value is at most {MaxValueBytes} bytes; received {value.Length}.", nameof(value));
        }

        return new LongfellowJwtAttribute(id, value);
    }


    /// <summary>
    /// Constructs the attribute from strings, encoded as UTF-8 — the encoding JSON payloads carry, so a claim
    /// value with non-ASCII text matches the decoded payload byte for byte (JOSE claim names themselves are
    /// ASCII, where the two encodings coincide).
    /// </summary>
    /// <param name="id">The identifier.</param>
    /// <param name="value">The value.</param>
    /// <returns>The attribute.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="id"/> or <paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When either side exceeds its capacity.</exception>
    public static LongfellowJwtAttribute FromStrings(string id, string value)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentNullException.ThrowIfNull(value);

        return Create(Encoding.UTF8.GetBytes(id), Encoding.UTF8.GetBytes(value));
    }


    /// <summary>Bridges this attribute to the statement's internal witness type.</summary>
    /// <returns>The internal opened-attribute view over the same identifier and value bytes.</returns>
    internal LongfellowJwtOpenedAttribute ToOpenedAttribute() => new LongfellowJwtOpenedAttribute(Id, Value);
}
