using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The cross-field MAC computation the reference applies to the three common values e, dpkx, dpky, a port
/// of google/longfellow-zk's <c>compute_macs</c> (<c>lib/circuits/mdoc/mdoc_zk.cc</c>) and
/// <c>MACReference::compute</c> (<c>lib/circuits/mac/mac_reference.h</c>): each value's two 16-byte halves
/// <c>m</c> are MAC'd as <c>mac = (av + ap)·m</c> over GF(2^128). The six per-element MAC keys <c>ap</c> and
/// the post-commit key <c>av</c> are non-deterministic in the reference (drawn from a secure engine), so
/// this verifies the MAC RELATION against the reference's own anchor <c>ap</c>/<c>av</c>/<c>mac</c> values
/// rather than regenerating them — the portable check that the computation is byte-faithful.
/// </summary>
internal static class MdocMacComputation
{
    /// <summary>
    /// The backend scalar width in bytes.
    /// </summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The width in bytes of one GF(2^128) element, and so of one message
    /// half.
    /// </summary>
    private const int ElementBytes = 16;

    /// <summary>
    /// The GF(2^128) addition delegate used to combine <c>av</c> and
    /// <c>ap</c> into the per-half MAC key.
    /// </summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>
    /// The GF(2^128) multiplication delegate used to compute
    /// <c>(av + ap)·m</c>.
    /// </summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();


    /// <summary>
    /// Verifies that the anchor MAC values in the reference column equal <c>(av + ap)·m</c> for the three
    /// common values recovered from the credential. <paramref name="macPublicStart"/> is the element index
    /// of the first MAC (the six macs then av, the seven public mac slots);
    /// <paramref name="macKeysStart"/> is the element index of the first private ap key (six keys).
    /// </summary>
    public static void AssertMatchesAnchor(byte[] referenceColumn, int macPublicStart, int macKeysStart, byte[] credential, MdocRequestedAttribute attribute)
    {
        ArgumentNullException.ThrowIfNull(referenceColumn);
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(attribute);

        MdocParsedDocument parsed = MdocParsedDocument.Parse(credential);
        MdocHashWitnessState state = MdocHashWitnessState.Compute(parsed, attribute);

        //The three common values' to_bytes_field (little-endian) bytes (the MAC messages).
        byte[][] messages = [state.MacMessageE, state.MacMessageDpkx, state.MacMessageDpky];

        //The six ap keys and av from the anchor.
        byte[][] ap = new byte[6][];
        for(int i = 0; i < 6; i++)
        {
            ap[i] = ReferenceElementToScalar(referenceColumn, macKeysStart + i);
        }

        //The seven public slots: six macs then av.
        byte[] av = ReferenceElementToScalar(referenceColumn, macPublicStart + 6);

        for(int i = 0; i < 3; i++)
        {
            for(int half = 0; half < 2; half++)
            {
                byte[] m = HalfToScalar(messages[i], half);
                byte[] expectedMac = ReferenceElementToScalar(referenceColumn, macPublicStart + 2 * i + half);

                byte[] keyed = new byte[ScalarSize];
                Add(av, ap[2 * i + half], keyed, CurveParameterSet.None);
                byte[] computed = new byte[ScalarSize];
                Multiply(keyed, m, computed, CurveParameterSet.None);

                Assert.IsTrue(computed.AsSpan().SequenceEqual(expectedMac), $"mac[{i}][{half}] must equal (av + ap)·m against the anchor.");
            }
        }
    }


    /// <summary>
    /// The message half <paramref name="half"/> of <paramref name="message"/>,
    /// read as <c>of_bytes_field(msg[half*16 .. +16])</c>: the 16
    /// big-endian bytes of that half interpreted as a GF(2^128) element in
    /// low-16, little-endian form, then packed into the low 16 big-endian
    /// bytes of a full-width backend scalar.
    /// </summary>
    private static byte[] HalfToScalar(byte[] message, int half)
    {
        byte[] scalar = new byte[ScalarSize];
        //of_bytes_field reads the 16 bytes little-endian: byte j contributes to bit 8*j. The backend stores
        //the element big-endian in [16, 32), so byte j (LE) maps to canonical[31 - j].
        for(int j = 0; j < ElementBytes; j++)
        {
            scalar[ScalarSize - 1 - j] = message[half * ElementBytes + j];
        }

        return scalar;
    }


    /// <summary>
    /// The little-endian element at <paramref name="elementIndex"/> in
    /// <paramref name="referenceColumn"/>, repacked as a 32-byte backend
    /// scalar with the element in its low 16 big-endian bytes.
    /// </summary>
    private static byte[] ReferenceElementToScalar(byte[] referenceColumn, int elementIndex)
    {
        ReadOnlySpan<byte> littleEndian = referenceColumn.AsSpan(elementIndex * ElementBytes, ElementBytes);
        byte[] scalar = new byte[ScalarSize];
        for(int j = 0; j < ElementBytes; j++)
        {
            scalar[ScalarSize - 1 - j] = littleEndian[j];
        }

        return scalar;
    }
}
