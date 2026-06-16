using System;
using System.Formats.Cbor;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Forward-only navigation over the definite-length CBOR maps and arrays of a real ISO 18013-5
/// mdoc DeviceResponse, on top of <see cref="CborReader"/>. <c>ReadEncodedValue</c> returns a
/// value's verbatim encoded bytes, so a sub-structure can be re-read independently (or spliced
/// into a COSE Sig_structure) without re-encoding it. Text-keyed maps only — COSE integer-keyed
/// headers are handled where they occur.
/// </summary>
internal static class CborNavigation
{
    //The encoded value bytes for the given text key in a text-keyed map, or null if absent.
    public static byte[]? MapValue(ReadOnlyMemory<byte> mapBytes, string key)
    {
        var reader = new CborReader(mapBytes);
        int count = reader.ReadStartMap() ?? throw new FormatException("Indefinite-length maps are not used by mdoc.");
        for(int i = 0; i < count; i++)
        {
            string itemKey = reader.ReadTextString();
            if(itemKey == key)
            {
                return reader.ReadEncodedValue().ToArray();
            }

            reader.SkipValue();
        }

        return null;
    }


    public static byte[] RequireMapValue(ReadOnlyMemory<byte> mapBytes, string key) =>
        MapValue(mapBytes, key) ?? throw new FormatException($"The map has no '{key}' entry.");


    //The verbatim encoded bytes of each element of a definite-length array.
    public static byte[][] ArrayElements(ReadOnlyMemory<byte> arrayBytes)
    {
        var reader = new CborReader(arrayBytes);
        int count = reader.ReadStartArray() ?? throw new FormatException("Indefinite-length arrays are not used by mdoc.");
        var elements = new byte[count][];
        for(int i = 0; i < count; i++)
        {
            elements[i] = reader.ReadEncodedValue().ToArray();
        }

        return elements;
    }
}
