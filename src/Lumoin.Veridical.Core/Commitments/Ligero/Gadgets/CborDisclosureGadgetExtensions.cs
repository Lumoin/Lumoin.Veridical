using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;

/// <summary>
/// Selective disclosure over a witnessed message, as extension methods on
/// <see cref="LigeroConstraintSystemBuilder"/>: proves a public byte pattern — an
/// "approximately CBOR" attribute encoding, e.g. the text key <c>age_over_18</c> followed by
/// the boolean <c>true</c> — appears at a witnessed offset in the message, via a one-hot
/// selector over the valid start positions. Combined with the in-circuit SHA-256 + ECDSA
/// binding, this ties a disclosed attribute to the signed bytes without revealing the rest of
/// the message — the role the reference <c>mdoc_hash</c> circuit's <c>OpenedAttribute</c> /
/// <c>AttrShift</c> structures play.
/// </summary>
/// <remarks>
/// The match is existential: the proof shows the pattern occurs <em>somewhere</em> (at the
/// one-hot position), not at a specific public offset, which is what selective disclosure
/// needs. The message bytes here are witnessed independently; binding them to the bytes the
/// SHA-256 gadget hashes (so the located attribute is in the <em>signed</em> message) is the
/// integration step that shares one witnessed message between the two gadgets.
/// </remarks>
internal static class CborDisclosureGadgetExtensions
{
    private const int ScalarSize = Scalar.SizeBytes;


    //Witnesses a message as one wire per byte (the byte's integer value).
    public static int[] WitnessMessage(this LigeroConstraintSystemBuilder builder, ReadOnlySpan<byte> message)
    {
        ArgumentNullException.ThrowIfNull(builder);

        int[] messageBytes = new int[message.Length];
        Span<byte> value = stackalloc byte[ScalarSize];
        for(int i = 0; i < message.Length; i++)
        {
            LigeroConstraintSystemBuilder.EncodeConstant(message[i], value);
            messageBytes[i] = builder.AddWire(value);
        }

        return messageBytes;
    }


    //Asserts the public pattern appears in messageBytes at the witnessed offset. A one-hot
    //selector over the valid start positions [0, n − l] picks the offset; for each pattern
    //byte the selected message byte (Σ selector[j]·message[j+i]) is pinned to the pattern, so
    //the existence of the match — not a specific public offset — is what is proven.
    public static void AssertContainsAt(this LigeroConstraintSystemBuilder builder, int[] messageBytes, int offset, ReadOnlySpan<byte> pattern)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(messageBytes);

        ReadOnlyMemory<byte> one = One();
        int[] selector = BuildSelector(builder, messageBytes.Length, pattern.Length, offset);

        //Σ_j selector[j]·message[j+i] = pattern[i] (a public constant).
        Span<byte> target = stackalloc byte[ScalarSize];
        for(int i = 0; i < pattern.Length; i++)
        {
            var terms = new LinearTerm[selector.Length];
            for(int j = 0; j < selector.Length; j++)
            {
                terms[j] = new LinearTerm(builder.Multiply(selector[j], messageBytes[j + i]), one);
            }

            LigeroConstraintSystemBuilder.EncodeConstant(pattern[i], target);
            builder.AddLinear(target, terms);
        }
    }


    //Like AssertContainsAt but the pattern is wire-valued (a value derived in-circuit, e.g. a
    //SHA-256 digest of an inner item), so it proves an outer message contains a computed digest
    //— the inner level of the two-level mdoc chain (the MSO holds SHA-256 of each signed item).
    public static void AssertContainsBytesAt(this LigeroConstraintSystemBuilder builder, int[] messageBytes, int offset, int[] patternByteWires)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(messageBytes);
        ArgumentNullException.ThrowIfNull(patternByteWires);

        ReadOnlyMemory<byte> one = One();
        byte[] negativeOne = new byte[ScalarSize];
        builder.Negate(one.Span, negativeOne);
        byte[] zero = new byte[ScalarSize];

        int[] selector = BuildSelector(builder, messageBytes.Length, patternByteWires.Length, offset);

        //Σ_j selector[j]·message[j+i] − patternByteWires[i] = 0.
        for(int i = 0; i < patternByteWires.Length; i++)
        {
            var terms = new LinearTerm[selector.Length + 1];
            for(int j = 0; j < selector.Length; j++)
            {
                terms[j] = new LinearTerm(builder.Multiply(selector[j], messageBytes[j + i]), one);
            }

            terms[selector.Length] = new LinearTerm(patternByteWires[i], negativeOne);
            builder.AddLinear(zero, terms);
        }
    }


    //A one-hot selector over the valid start positions [0, n − l]: exactly one position chosen.
    private static int[] BuildSelector(LigeroConstraintSystemBuilder builder, int messageLength, int patternLength, int offset)
    {
        int positions = messageLength - patternLength + 1;
        if(positions <= 0)
        {
            throw new ArgumentException("The pattern is longer than the message.", nameof(patternLength));
        }

        ReadOnlyMemory<byte> one = One();
        int[] selector = new int[positions];
        Span<byte> bit = stackalloc byte[ScalarSize];
        for(int j = 0; j < positions; j++)
        {
            LigeroConstraintSystemBuilder.EncodeConstant((uint)(j == offset ? 1 : 0), bit);
            selector[j] = builder.AddBit(bit);
        }

        var selectorTerms = new LinearTerm[positions];
        for(int j = 0; j < positions; j++)
        {
            selectorTerms[j] = new LinearTerm(selector[j], one);
        }

        builder.AddLinear(one.Span, selectorTerms);

        return selector;
    }


    private static byte[] One()
    {
        byte[] one = new byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(1, one);

        return one;
    }
}
