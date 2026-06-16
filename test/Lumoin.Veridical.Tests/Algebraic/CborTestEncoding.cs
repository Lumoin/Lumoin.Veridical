using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Minimal CBOR encodings for building the approximately-CBOR attribute fragments the
/// disclosure gadget tests search for: a text key followed by a boolean value (the mdoc
/// <c>age_over_NN = true/false</c> shape). Named so the tests read as attributes, not bytes.
/// </summary>
internal static class CborTestEncoding
{
    //CBOR simple values: boolean true / false.
    public const byte True = 0xF5;
    public const byte False = 0xF4;

    //Major type 3 (text string) with a definite short length (≤ 23) packed into the head byte.
    public static byte TextStringHeader(int length) => (byte)(0x60 | length);


    //The CBOR encoding of a text key followed by a boolean value, e.g. ("age_over_18", true).
    public static byte[] BooleanAttribute(string key, bool value)
    {
        ArgumentNullException.ThrowIfNull(key);

        byte[] keyBytes = Encoding.UTF8.GetBytes(key);

        return [TextStringHeader(keyBytes.Length), .. keyBytes, value ? True : False];
    }
}
