using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The GF(2^128) hash-circuit WITNESS FILLER (conformance step C.11): the C# port of the column that
/// google/longfellow-zk's <c>fill_witness</c> (<c>lib/circuits/mdoc/mdoc_zk.cc</c>) plus
/// <c>MdocHashWitness::fill_witness</c> (<c>lib/circuits/mdoc/mdoc_witness.h</c>) lay into the hash
/// circuit's dense input array for a single-attribute version-7 mdoc proof. Every deterministic region —
/// the public attribute/timestamp encodings, the SHA-256 preimage bits and block witnesses, the CBOR
/// indices, the attribute opening witnesses — is reproduced byte-for-byte; the thirteen MAC-randomness
/// slots (the six per-element MAC keys and the seven post-commit MAC/av slots) come from a
/// <see cref="System.Security.Cryptography"/>-grade engine in the reference and cannot be regenerated from
/// the credential, so they are left to the caller (the witness-column gate splices the reference dump for
/// them, and <see cref="MdocMacComputation"/> verifies the MAC algebra against the dump).
/// </summary>
/// <remarks>
/// <para>
/// Every element is a GF(2^128) field element stored as 32 canonical big-endian bytes (the
/// <see cref="Gf2k128Backend"/> representation, with the 16-byte field element in the low half).
/// <c>to_bytes_field</c> for the witness fixture is the low 16 big-endian bytes reversed to little-endian.
/// </para>
/// <para>
/// The column region map (one-attribute, version 7; total 85118 elements):
/// </para>
/// <list type="bullet">
///   <item><description><b>[0]</b> the constant-one wire (<c>Fs.one()</c>).</description></item>
///   <item><description><b>[1, 785)</b> the attribute encoding: 96 zero-padded value bytes as 768 bits, then the 8-bit identifier length and the 8-bit value length (<c>fill_attribute</c>, version 7).</description></item>
///   <item><description><b>[785, 945)</b> the 20-byte <c>now</c> timestamp as 160 bits (<c>fill_bit_string</c>).</description></item>
///   <item><description><b>[945, 952)</b> the six MAC values and the av key (zero at fill time, overwritten by <c>update_macs</c> after the commit). This is <c>npub_in = 952</c>.</description></item>
///   <item><description><b>[952, 1720)</b> the three 32-byte MAC messages e, dpkx, dpky as 768 bits.</description></item>
///   <item><description><b>[1720, 85112)</b> the SHA section and CBOR/attribute witnesses (<c>MdocHashWitness::fill_witness</c>): the 8-bit block index, the 40-block SHA preimage bytes as bits, the 40 block witnesses (plucked), the four CBOR key indices, and the attribute opening witness (128 bytes as bits, two attribute-block SHA witnesses, the MSO value index, the ei/ev shifts, the salted-hash layout).</description></item>
///   <item><description><b>[85112, 85118)</b> the six MAC keys (ap), the reference's non-deterministic randomness.</description></item>
/// </list>
/// </remarks>
internal sealed class MdocHashWitnessFiller
{
    private const int ScalarSize = 32;

    private const int MaxShaBlocks = 40;
    private const int Cose1PrefixLength = 18;
    private const int CborIndexBits = 12;
    private const int ShaPluckerBits = 4;
    private const int ShaPluckerCount = 1 << ShaPluckerBits;
    private const int ShaPackedWordElements = (32 + ShaPluckerBits - 1) / ShaPluckerBits;

    //The 18-byte COSE1 prefix prepended to the tagged MSO before hashing (mdoc_constants.h kCose1Prefix).
    private static readonly byte[] Cose1Prefix =
    [
        0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75,
        0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x59,
    ];

    private readonly ScalarAddDelegate add;
    private readonly Lch14AdditiveFft fft;
    private readonly byte[][] pluckerCodes;
    private readonly byte[] one;
    private readonly byte[] zero;

    private readonly List<byte[]> column = [];


    public MdocHashWitnessFiller(Lch14AdditiveFft fft, ScalarAddDelegate add)
    {
        ArgumentNullException.ThrowIfNull(fft);
        ArgumentNullException.ThrowIfNull(add);
        this.fft = fft;
        this.add = add;

        zero = new byte[ScalarSize];
        one = new byte[ScalarSize];
        one[ScalarSize - 1] = 0x01;

        pluckerCodes = BuildPluckerCodes();
    }


    /// <summary>
    /// Builds the complete hash-circuit witness column for the one-attribute version-7 mdoc proof over
    /// <paramref name="mdoc"/> (the raw DeviceResponse bytes) disclosing <paramref name="attribute"/>, with
    /// the verifier-supplied current time <paramref name="now"/>. The thirteen MAC-randomness slots are left
    /// as zero (the caller splices them); every other element is the reference's exact value.
    /// </summary>
    public byte[] Fill(byte[] mdoc, MdocRequestedAttribute attribute, ReadOnlySpan<byte> now)
    {
        ArgumentNullException.ThrowIfNull(mdoc);
        ArgumentNullException.ThrowIfNull(attribute);

        var parsed = MdocParsedDocument.Parse(mdoc);

        //fill_attributes: the constant-one wire, then fill_attribute, then the now bit string.
        Push(one);
        FillAttribute(attribute);
        FillBitString(now, 20, 20);

        //init mac+av to 0 (6 macs + 1 av). update_macs overwrites these post-commit.
        for(int i = 0; i < 7; i++)
        {
            Push(zero);
        }

        //The hash witness intermediate values (compute_witness in MdocHashWitness).
        MdocHashWitnessState state = MdocHashWitnessState.Compute(parsed, attribute);

        //The three 32-byte MAC messages e, dpkx, dpky as bit strings (sw->compute_witness loop).
        FillBitString(state.MacMessageE, 32, 32);
        FillBitString(state.MacMessageDpkx, 32, 32);
        FillBitString(state.MacMessageDpky, 32, 32);

        //MdocHashWitness::fill_witness.
        FillHashWitness(parsed, state);

        //The three MacGF2Witness fills (state.macs[i].ap_[0], ap_[1]) are the reference's random keys. Fill
        //the SHARED chosen ap keys (MdocSignatureWitnessFiller.Ap) so the hash and sig circuits commit the
        //SAME ap — the cross-field MAC binding (the dual-field driver gate, C3a). The byte-exact crown/real
        //hash gates splice the reference dump over these six slots afterwards, so this fill is invisible to
        //them; only the dual-field driver (which does NOT splice) reads the chosen keys here.
        byte[][] ap = MdocSignatureWitnessFiller.Ap;
        for(int i = 0; i < 6; i++)
        {
            Push(ap[i]);
        }

        return Flatten();
    }


    /// <summary>The element count the fill produced (must equal the circuit's input count).</summary>
    public int Count => column.Count;


    //fill_attribute (version >= 7): 96 zero-padded value bytes as bits, then the 8-bit id length and the
    //8-bit value length, both as the comparison-string lengths the v7 circuit forms.
    private void FillAttribute(MdocRequestedAttribute attribute)
    {
        byte[] valueBytes = new byte[96];

        //"<len(id)> <id>" in the first 32 bytes.
        var textLengthHeader = new List<byte>();
        AppendTextLength(textLengthHeader, attribute.Id.Length);
        for(int j = 0; j < attribute.Id.Length; j++)
        {
            textLengthHeader.Add(attribute.Id[j]);
        }

        for(int j = 0; j < textLengthHeader.Count && j < 32; j++)
        {
            valueBytes[j] = textLengthHeader[j];
        }

        //The cbor value in the next 64 bytes.
        for(int j = 0; j < 64 && j < attribute.CborValue.Length; j++)
        {
            valueBytes[32 + j] = attribute.CborValue[j];
        }

        for(int i = 0; i < 96; i++)
        {
            PushByteBits(valueBytes[i]);
        }

        //"<17> elementIdentifier <id>" comparison length: 1 + 17 + 1 + id_len.
        PushNumberBits((ulong)(1 + 17 + 1 + attribute.Id.Length), 8);

        //"<12> elementValue <cbor_value>" comparison length: cbor_value_len + 12 + 1.
        PushNumberBits((ulong)(attribute.CborValue.Length + 12 + 1), 8);
    }


    //MdocHashWitness::fill_witness, version 7.
    private void FillHashWitness(MdocParsedDocument parsed, MdocHashWitnessState state)
    {
        PushNumberBits(state.NumBlocks, 8);

        //The SHA preimage bytes from kCose1PrefixLen up to max_shablocks * 64, as bytes.
        for(int i = Cose1PrefixLength; i < MaxShaBlocks * 64; i++)
        {
            PushByteBits(state.SignedBytes[i]);
        }

        for(int j = 0; j < MaxShaBlocks; j++)
        {
            FillSha(state.MsoBlocks[j]);
        }

        //The four CBOR key indices (header positions within the MSO after the 5-byte tag).
        PushNumberBits((ulong)parsed.ValidFromKeyPos, CborIndexBits);
        PushNumberBits((ulong)parsed.ValidUntilKeyPos, CborIndexBits);
        PushNumberBits((ulong)parsed.DeviceKeyInfoKeyPos, CborIndexBits);
        PushNumberBits((ulong)parsed.ValueDigestsKeyPos, CborIndexBits);

        //The attribute opening witness (single attribute).
        MdocAttributeWitness attributeWitness = state.AttributeWitness;
        for(int i = 0; i < 2 * 64; i++)
        {
            PushByteBits(attributeWitness.AttributeBytes[i]);
        }

        for(int j = 0; j < 2; j++)
        {
            FillSha(attributeWitness.Blocks[j]);
        }

        //attr_mso.v: the value header position of the digest entry in the MSO.
        PushNumberBits((ulong)attributeWitness.MsoValuePos, CborIndexBits);

        //attr_ei (offset, len), attr_ev (offset, len).
        PushNumberBits((ulong)attributeWitness.IdentifierOffset, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.IdentifierLength, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.ValueOffset, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.ValueLength, CborIndexBits);

        //The salted-hash layout (version 7).
        PushNumberBits((ulong)attributeWitness.SaltedI1, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.SaltedI2, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.SaltedI3, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.SaltedL0, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.SaltedL1, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.SaltedL2, CborIndexBits);
        PushNumberBits((ulong)attributeWitness.SaltedL3, CborIndexBits);
        PushNumberBits(attributeWitness.SaltedPermutation, 8);
    }


    //fill_sha: 48 outw, then 64 (oute, outa) pairs, then 8 h1, each plucked four bits at a time.
    private void FillSha(MdocFlatSha256Witness.BlockWitness block)
    {
        for(int k = 0; k < 48; k++)
        {
            PushPackedWord(block.OutW[k]);
        }

        for(int k = 0; k < 64; k++)
        {
            PushPackedWord(block.OutE[k]);
            PushPackedWord(block.OutA[k]);
        }

        for(int k = 0; k < 8; k++)
        {
            PushPackedWord(block.H1[k]);
        }
    }


    //BitPluckerEncoder::mkpacked_v32: 8 elements, each encode((j >> 4k) & 15).
    private void PushPackedWord(uint word)
    {
        uint remaining = word;
        for(int i = 0; i < ShaPackedWordElements; i++)
        {
            Push(pluckerCodes[remaining & (ShaPluckerCount - 1)]);
            remaining >>= ShaPluckerBits;
        }
    }


    //fill_bit_string: len*8 bits of s padded to max*8 with the field value 2 for the unused tail.
    private void FillBitString(ReadOnlySpan<byte> bytes, int length, int max)
    {
        byte[] twoElement = OfScalar(2);
        for(int i = 0; i < max; i++)
        {
            if(i < length && i < bytes.Length)
            {
                PushByteBits(bytes[i]);
            }
            else
            {
                for(int j = 0; j < 8; j++)
                {
                    Push(twoElement);
                }
            }
        }
    }


    //fill_byte: the eight bits of b as of_scalar(bit), least-significant first.
    private void PushByteBits(byte b)
    {
        for(int j = 0; j < 8; j++)
        {
            Push(((b >> j) & 0x1) != 0 ? one : zero);
        }
    }


    //push_back(x, bits, F): the low bits of x as of_scalar(bit), least-significant first.
    private void PushNumberBits(ulong x, int bits)
    {
        for(int i = 0; i < bits; i++)
        {
            Push(((x >> i) & 1) != 0 ? one : zero);
        }
    }


    private void Push(byte[] element)
    {
        column.Add(element);
    }


    private byte[] Flatten()
    {
        byte[] result = new byte[column.Count * ScalarSize];
        for(int i = 0; i < column.Count; i++)
        {
            column[i].CopyTo(result.AsSpan(i * ScalarSize, ScalarSize));
        }

        return result;
    }


    //The 16 SHA plucker codes encode(v) = of_scalar(2v) - of_scalar(15) over GF(2^128) (subtraction is XOR).
    private byte[][] BuildPluckerCodes()
    {
        byte[] ofScalar15 = OfScalar(15);
        var codes = new byte[ShaPluckerCount][];
        for(int v = 0; v < ShaPluckerCount; v++)
        {
            byte[] code = new byte[ScalarSize];
            add(OfScalar((uint)(2 * v)), ofScalar15, code, CurveParameterSet.None);
            codes[v] = code;
        }

        return codes;
    }


    //of_scalar(u): the GF(2^128) element Σ_bit β_bit (the LCH14 production-16 subfield basis), exactly the
    //reference's GF2_128::of_scalar over the same subfield (matched by the C.9/C.10 anchor gates).
    private byte[] OfScalar(uint value)
    {
        byte[] accumulator = new byte[ScalarSize];
        int bit = 0;
        uint remaining = value;
        while(remaining != 0)
        {
            if((remaining & 1) != 0)
            {
                add(accumulator, fft.BasisElement(bit), accumulator, CurveParameterSet.None);
            }

            remaining >>= 1;
            bit++;
        }

        return accumulator;
    }


    //append_text_len: the cbor text-string length header for a string up to 255 bytes.
    private static void AppendTextLength(List<byte> buffer, int length)
    {
        if(length < 24)
        {
            buffer.Add((byte)(0x60 + length));
        }
        else
        {
            buffer.Add(0x78);
            buffer.Add((byte)length);
        }
    }


    /// <summary>The 16 plucker codes the SHA witness packs, exposed for the region gate.</summary>
    public byte[][] PluckerCodes => pluckerCodes;


    /// <summary>The 18-byte COSE1 prefix, exposed for the preimage gate.</summary>
    public static ReadOnlySpan<byte> Cose1PrefixBytes => Cose1Prefix;
}
