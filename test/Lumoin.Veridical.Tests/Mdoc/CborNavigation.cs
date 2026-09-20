using Lumoin.Veritas.Cbor;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Forward-only navigation over the definite-length CBOR maps and arrays of a real ISO 18013-5
/// mdoc DeviceResponse, on top of <see cref="CborReader"/>. <see cref="EncodedValue"/> returns a
/// value's verbatim encoded bytes — the source between the reader's position before and after the
/// item — so a sub-structure can be re-read independently (or spliced into a COSE Sig_structure)
/// without re-encoding it. Text-keyed maps only — COSE integer-keyed headers are handled where they
/// occur.
/// </summary>
internal static class CborNavigation
{
    /// <summary>
    /// The options every test-side CBOR reader and writer runs with: RFC 8949 default conformance. The mdoc
    /// structures are definite-length and nothing here needs canonical map ordering.
    /// </summary>
    public static CborSerializerOptions Options { get; } = new();


    /// <summary>The encoded value bytes for the given text key in a text-keyed map, or null if absent.</summary>
    public static byte[]? MapValue(ReadOnlyMemory<byte> mapBytes, string key)
    {
        var reader = new CborReader(mapBytes, Options);
        int count = reader.ReadStartMap() ?? throw new FormatException("Indefinite-length maps are not used by mdoc.");
        for(int i = 0; i < count; i++)
        {
            string itemKey = reader.ReadTextString();
            if(itemKey == key)
            {
                return EncodedValue(reader, mapBytes);
            }

            SkipValue(reader);
        }

        return null;
    }


    /// <summary>The encoded value bytes for the given text key in a text-keyed map; the map must hold the key.</summary>
    public static byte[] RequireMapValue(ReadOnlyMemory<byte> mapBytes, string key) =>
        MapValue(mapBytes, key) ?? throw new FormatException($"The map has no '{key}' entry.");


    /// <summary>The verbatim encoded bytes of each element of a definite-length array.</summary>
    public static byte[][] ArrayElements(ReadOnlyMemory<byte> arrayBytes)
    {
        var reader = new CborReader(arrayBytes, Options);
        int count = reader.ReadStartArray() ?? throw new FormatException("Indefinite-length arrays are not used by mdoc.");
        var elements = new byte[count][];
        for(int i = 0; i < count; i++)
        {
            elements[i] = EncodedValue(reader, arrayBytes);
        }

        return elements;
    }


    /// <summary>
    /// The verbatim bytes of the next data item of <paramref name="reader"/>, which reads
    /// <paramref name="source"/>: the item is consumed whole and the source is sliced between the positions
    /// before and after it.
    /// </summary>
    public static byte[] EncodedValue(CborReader reader, ReadOnlyMemory<byte> source)
    {
        ArgumentNullException.ThrowIfNull(reader);

        int start = reader.BytesConsumed;
        SkipValue(reader);

        return source[start..reader.BytesConsumed].ToArray();
    }


    /// <summary>
    /// Consumes the next data item whole, nested containers included, without decoding it into anything.
    /// Tags are prefixes and do not count as items; a definite array of <c>n</c> holds <c>n</c> items and a
    /// definite map of <c>n</c> holds <c>2n</c>. Indefinite-length containers are refused, as mdoc never
    /// encodes them.
    /// </summary>
    public static void SkipValue(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        //The items still to consume in each enclosing container, innermost last, and whether it is a map.
        var enclosing = new Stack<(int Remaining, bool IsMap)>();
        int remaining = 1;
        bool isMap = false;
        while(true)
        {
            if(remaining == 0)
            {
                if(enclosing.Count == 0)
                {
                    return;
                }

                CloseContainer(reader, isMap);
                (remaining, isMap) = enclosing.Pop();

                continue;
            }

            CborReaderState state = reader.PeekState();
            if(state is CborReaderState.Tag)
            {
                reader.ReadTag();

                continue;
            }

            if(state is CborReaderState.StartArray or CborReaderState.StartMap)
            {
                int? length = state is CborReaderState.StartArray ? reader.ReadStartArray() : reader.ReadStartMap();
                int items = length ?? throw new FormatException("Indefinite-length containers are not used by mdoc.");
                enclosing.Push((remaining - 1, isMap));
                isMap = state is CborReaderState.StartMap;
                remaining = isMap ? 2 * items : items;

                continue;
            }

            ScalarReader(state)(reader);
            remaining--;
        }
    }


    /// <summary>Closes the container <paramref name="reader"/> has consumed the last item of.</summary>
    private static void CloseContainer(CborReader reader, bool isMap)
    {
        if(isMap)
        {
            reader.ReadEndMap();
        }
        else
        {
            reader.ReadEndArray();
        }
    }


    /// <summary>The read that consumes one scalar item in <paramref name="state"/>, its value discarded.</summary>
    private static Action<CborReader> ScalarReader(CborReaderState state) => state switch
    {
        CborReaderState.UnsignedInteger => static reader => reader.ReadUInt64(),
        CborReaderState.NegativeInteger => static reader => reader.ReadCborNegativeIntegerRepresentation(),
        CborReaderState.ByteString => static reader => reader.ReadByteStringSpan(),
        CborReaderState.TextString => static reader => reader.ReadTextString(),
        CborReaderState.Boolean => static reader => reader.ReadBoolean(),
        CborReaderState.Null => static reader => reader.ReadNull(),
        CborReaderState.Undefined => static reader => reader.ReadUndefined(),
        CborReaderState.SimpleValue => static reader => reader.ReadSimpleValue(),
        CborReaderState.HalfPrecisionFloat => static reader => reader.ReadHalf(),
        CborReaderState.SinglePrecisionFloat => static reader => reader.ReadSingle(),
        CborReaderState.DoublePrecisionFloat => static reader => reader.ReadDouble(),
        _ => throw new FormatException($"A data item was expected but the reader is at {state}."),
    };
}
