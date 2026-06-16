using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The Fp256 mdoc SIGNATURE-circuit WITNESS FILLER: the C# port of the 3739-element dense input column that
/// google/longfellow-zk's <c>fill_witness</c> (<c>tempdocs/longfellow-zk-reference/lib/circuits/mdoc/mdoc_zk.cc</c>,
/// the <c>fill_b</c> / <c>Fp256Base</c> side) plus <c>MdocSignatureWitness::fill_witness</c>
/// (<c>lib/circuits/mdoc/mdoc_witness.h:603-613</c>) lay into the version-7 SIG circuit for a one-attribute
/// mdoc proof. The column splits 900 public + 2839 private.
/// </summary>
/// <remarks>
/// <para>
/// Every element is a canonical (non-Montgomery) base-field value emitted as 32 big-endian bytes — the
/// established C# filler convention (the reference's <c>to_bytes_field</c> little-endian conversion is
/// applied only at the Phase-6 public-input/coefficient boundary). The two ECDSA halves reuse
/// <see cref="EcdsaSignatureWitness"/> unchanged: the ISSUER half over the REAL credential's
/// <c>(pkX, pkY, e_, r, s)</c> and the DEVICE half over the SYNTHESIZED <c>(dpkx, dpky, e2, r2, s2)</c>
/// (coordinator decision OQ1).
/// </para>
/// <para>
/// The column region map (one-attribute, version 7; total 3739 elements):
/// </para>
/// <list type="bullet">
///   <item><description><b>[0,4)</b> <c>one</c>, <c>pkX</c>, <c>pkY</c>, <c>e2</c> (fill_signature_inputs, mdoc_zk.cc:167-173). <c>e2</c> is the DEVICE/transcript hash (PUBLIC, OQ6).</description></item>
///   <item><description><b>[4,772)</b> the six MACs, each a 128-bit GF(2^128) value expanded to 128 Fp256 one/zero wires (fill_gf2k, mac_reference.h:63).</description></item>
///   <item><description><b>[772,900)</b> the <c>av</c> key, 128 Fp256 one/zero wires. This is <c>npub_in = 900</c>.</description></item>
///   <item><description><b>[900,903)</b> the issuer hash <c>e_</c>, the device key <c>dpkx</c>, <c>dpky</c> (MdocSignatureWitness::fill_witness).</description></item>
///   <item><description><b>[903,1937)</b> <c>ew_</c>: the ISSUER VerifyWitness3 column (1034, EcdsaSignatureWitness.Fill on the real issuer tuple).</description></item>
///   <item><description><b>[1937,2971)</b> <c>dkw_</c>: the DEVICE VerifyWitness3 column (1034, EcdsaSignatureWitness.Fill on the synth device tuple).</description></item>
///   <item><description><b>[2971,3739)</b> the three MacWitness fills (256 each: ap_[0]/ap_[1]/x_[0]/x_[1] packed 2-bits-at-a-time, kMACPluckerBits=2, kNv128Elts=64).</description></item>
/// </list>
/// <para>
/// The reference fills the public macs/av with <c>Fs.zero()</c> at commit and overwrites them post-commit
/// via <c>update_macs</c> (mdoc_zk.cc:247-249, 286-303). Here the two-phase commit/update is collapsed into
/// a single deterministic fill of the COMMITTED values: with chosen-constant <c>ap</c> keys and a chosen
/// <c>av</c> (OQ2), <c>mac[i] = (av + ap_i)·m_i</c> over GF(2^128) is computed and expanded, so the column
/// is directly provable. The <c>av</c> here is a fixed constant rather than the transcript-derived value.
/// </para>
/// </remarks>
internal sealed class MdocSignatureWitnessFiller
{
    private const int ScalarSize = 32;
    private const int Gf2kBits = 128;
    private const int Gf2kBytes = 16;
    private const int MacPluckerBits = 2;
    private const int MacPluckerCount = 1 << MacPluckerBits;
    private const int MacPackedWordElements = (Gf2kBits + MacPluckerBits - 1) / MacPluckerBits;

    /// <summary>The total SIG-circuit input count (npub_in 900 + private 2839).</summary>
    public const int ElementCount = 3739;

    /// <summary>The public-input count (one,pkX,pkY,e2 + 6 macs + av, each gf2k 128-bit-expanded).</summary>
    public const int PublicInputCount = 900;

    private static readonly BigInteger Prime = P256BaseFieldReference.FieldOrder;

    //The six per-element MAC keys ap and the verifier key av, chosen deterministic GF(2^128) constants
    //(OQ2). The MAC relation mac=(av+ap)·m is satisfied by construction for any choice; these are pinned for
    //reproducibility. Each is a fixed 16-byte little-endian polynomial (the gf2k of_bytes_field convention).
    private static readonly byte[] AvKey = Gf2kFromHexLittleEndian("a3f10e5572c4901bd6883f2147ac55e0");

    private static readonly byte[][] ApKeys =
    [
        Gf2kFromHexLittleEndian("11223344556677889900aabbccddeeff"),
        Gf2kFromHexLittleEndian("0102030405060708090a0b0c0d0e0f10"),
        Gf2kFromHexLittleEndian("f0e1d2c3b4a5968778695a4b3c2d1e0f"),
        Gf2kFromHexLittleEndian("00ffeeddccbbaa998877665544332211"),
        Gf2kFromHexLittleEndian("13579bdf02468ace13579bdf02468ace"),
        Gf2kFromHexLittleEndian("cafebabedeadbeef0123456789abcdef"),
    ];

    private static readonly ScalarAddDelegate GfAdd = Gf2k128Backend.GetAdd();
    private static readonly ScalarMultiplyDelegate GfMultiply = Gf2k128Backend.GetMultiply();
    private static readonly ScalarSubtractDelegate FpSubtract = P256BaseFieldReference.GetSubtract();

    private readonly byte[] one;
    private readonly byte[] zero;
    private readonly byte[][] pluckerCodes;

    private readonly List<byte[]> column = [];


    public MdocSignatureWitnessFiller()
    {
        zero = new byte[ScalarSize];
        one = new byte[ScalarSize];
        one[ScalarSize - 1] = 0x01;

        pluckerCodes = BuildPluckerCodes();
    }


    /// <summary>The element count the fill produced (must equal <see cref="ElementCount"/>).</summary>
    public int Count => column.Count;

    /// <summary>The four OQ4 2-bit MAC plucker codes <c>encode(v)=of_scalar(2v)−of_scalar(3)</c>, exposed for the gate.</summary>
    public byte[][] PluckerCodes => pluckerCodes;

    /// <summary>The chosen <c>av</c> key (OQ2), exposed for the MAC-algebra gate.</summary>
    public static byte[] Av => AvKey;

    /// <summary>The six chosen <c>ap</c> keys (OQ2), exposed for the MAC-algebra gate.</summary>
    public static byte[][] Ap => ApKeys;


    /// <summary>
    /// Builds the complete 3739-element SIG-circuit column in <c>fill_witness</c> order: the issuer half is
    /// the REAL credential's signature via <paramref name="issuer"/>, the device half is the synthesized
    /// tuple via <paramref name="device"/>. The macs/av are the committed values from the chosen keys.
    /// </summary>
    public byte[] Fill(MdocDisclosure issuer, MdocDeviceSignatureSynth device)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(device);

        BigInteger pkX = ToInteger(issuer.IssuerKeyX);
        BigInteger pkY = ToInteger(issuer.IssuerKeyY);
        BigInteger issuerHash = IssuerHash(issuer);
        BigInteger r = ToInteger(issuer.SignatureR);
        BigInteger s = ToInteger(issuer.SignatureS);

        BigInteger dpkx = device.DeviceKeyX;
        BigInteger dpky = device.DeviceKeyY;
        BigInteger e2 = device.DeviceHash;

        //The three common values whose MAC messages are to_bytes_field (little-endian) bytes: the issuer
        //hash e_, the synthesized device key dpkx, dpky (mdoc_zk.cc:258-264, the sw side common values).
        byte[][] macMessages =
        [
            ToBytesField(issuerHash),
            ToBytesField(dpkx),
            ToBytesField(dpky),
        ];

        //The committed macs: mac[i] = (av + ap_i)·m_i over GF(2^128) (mac_reference.h:43-51). Six macs (two
        //per common value), expanded with av into the public prefix.
        byte[][] macs = ComputeMacs(macMessages);

        //fill_signature_inputs (mdoc_zk.cc:169-172): one, pkX, pkY, e2 (e2 = the DEVICE hash, OQ6).
        Push(one);
        Push(Element(pkX));
        Push(Element(pkY));
        Push(Element(e2));

        //The six macs then av, each gf2k 128-bit-expanded to Fp256 one/zero wires (mdoc_zk.cc:204-207).
        for(int i = 0; i < 6; i++)
        {
            FillGf2k(macs[i]);
        }

        FillGf2k(AvKey);

        //MdocSignatureWitness::fill_witness (mdoc_witness.h:604-606): e_, dpkx_, dpky_.
        Push(Element(issuerHash));
        Push(Element(dpkx));
        Push(Element(dpky));

        //ew_: the ISSUER VerifyWitness3 column on the REAL credential tuple (mdoc_witness.h:608).
        AppendColumn(EcdsaSignatureWitness.Fill(pkX, pkY, issuerHash, r, s));

        //dkw_: the DEVICE VerifyWitness3 column on the SYNTH tuple (mdoc_witness.h:609).
        AppendColumn(EcdsaSignatureWitness.Fill(dpkx, dpky, e2, device.SignatureR, device.SignatureS));

        //The three MacWitness fills (mdoc_witness.h:610-612, mac_witness.h:38-54): per common value, the two
        //ap keys then the two message halves, each packed 2-bits-at-a-time.
        for(int i = 0; i < 3; i++)
        {
            FillMacWitness(ApKeys[2 * i], ApKeys[(2 * i) + 1], macMessages[i]);
        }

        return Flatten();
    }


    /// <summary>
    /// Builds the SIG-circuit column for the DUAL-FIELD DRIVER (C3): the issuer half over the REAL credential
    /// and the device half over the REAL extracted device tuple (<paramref name="device"/>), with the public
    /// mac/av region <c>[4, 900)</c> filled with ZEROS — the reference's commit-time state, which the driver
    /// overwrites post-commit via <c>update_macs</c> from the transcript-squeezed <c>a_v</c>
    /// (mdoc_zk.cc:247-249, 286-303). Unlike <see cref="Fill"/> (the self-consistent standalone column with
    /// chosen-constant macs collapsed in), this column is the driver's commit input.
    /// </summary>
    public byte[] FillForDriver(MdocDisclosure issuer, MdocDeviceSignature device)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(device);

        BigInteger pkX = ToInteger(issuer.IssuerKeyX);
        BigInteger pkY = ToInteger(issuer.IssuerKeyY);
        BigInteger issuerHash = IssuerHash(issuer);
        BigInteger r = ToInteger(issuer.SignatureR);
        BigInteger s = ToInteger(issuer.SignatureS);

        BigInteger dpkx = device.DeviceKeyX;
        BigInteger dpky = device.DeviceKeyY;
        BigInteger e2 = device.DeviceHash;

        //The three common values (e_, dpkx, dpky) as to_bytes_field bytes; the driver MAC-binds them.
        byte[][] macMessages =
        [
            ToBytesField(issuerHash),
            ToBytesField(dpkx),
            ToBytesField(dpky),
        ];

        //fill_signature_inputs (mdoc_zk.cc:169-172): one, pkX, pkY, e2 (e2 = the REAL device-auth hash).
        Push(one);
        Push(Element(pkX));
        Push(Element(pkY));
        Push(Element(e2));

        //init mac+av to 0 (6 macs + av), each gf2k 128-bit-expanded: 7 * 128 = 896 zero wires at [4, 900).
        //The driver overwrites these post-commit via update_macs.
        for(int i = 0; i < 7 * Gf2kBits; i++)
        {
            Push(zero);
        }

        //MdocSignatureWitness::fill_witness (mdoc_witness.h:604-606): e_, dpkx_, dpky_.
        Push(Element(issuerHash));
        Push(Element(dpkx));
        Push(Element(dpky));

        //ew_: the ISSUER VerifyWitness3 column on the REAL credential tuple (mdoc_witness.h:608).
        AppendColumn(EcdsaSignatureWitness.Fill(pkX, pkY, issuerHash, r, s));

        //dkw_: the DEVICE VerifyWitness3 column on the REAL extracted tuple (mdoc_witness.h:609).
        AppendColumn(EcdsaSignatureWitness.Fill(dpkx, dpky, e2, device.SignatureR, device.SignatureS));

        //The three MacWitness fills with the SHARED chosen ap keys (mdoc_witness.h:610-612).
        for(int i = 0; i < 3; i++)
        {
            FillMacWitness(ApKeys[2 * i], ApKeys[(2 * i) + 1], macMessages[i]);
        }

        return Flatten();
    }


    /// <summary>
    /// The three common values (<c>e_</c>, <c>dpkx</c>, <c>dpky</c>) the driver MAC-binds, as canonical
    /// 32-byte big-endian scalars: the issuer MSO hash, then the REAL device key coordinates. The driver's
    /// <c>compute_macs</c> consumes these, and they must be byte-identical to the hash filler's
    /// <c>MacMessageE/Dpkx/Dpky</c> after the shared convention (the cross-filler common-match gate asserts
    /// it).
    /// </summary>
    public static byte[] CommonValues(MdocDisclosure issuer, MdocDeviceSignature device)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(device);

        byte[] common = new byte[3 * ScalarSize];
        Element(IssuerHash(issuer)).CopyTo(common.AsSpan(0, ScalarSize));
        Element(device.DeviceKeyX).CopyTo(common.AsSpan(ScalarSize, ScalarSize));
        Element(device.DeviceKeyY).CopyTo(common.AsSpan(2 * ScalarSize, ScalarSize));

        return common;
    }


    /// <summary>The six shared <c>ap</c> keys concatenated as canonical 32-byte scalars (the driver's apKeys).</summary>
    public static byte[] ApKeyBytes()
    {
        byte[] keys = new byte[6 * ScalarSize];
        for(int i = 0; i < 6; i++)
        {
            ApKeys[i].CopyTo(keys.AsSpan(i * ScalarSize, ScalarSize));
        }

        return keys;
    }


    /// <summary>
    /// The issuer MSO hash <c>e_</c> (PRIVATE wire 900, OQ6): <c>nat_from_hash(tagged_mso_bytes_)</c> =
    /// SHA-256 of the COSE <c>Sig_structure</c> read big-endian (mdoc_witness.h:626, 391-398). The
    /// <c>tagged_mso_bytes_</c> is exactly <see cref="MdocDisclosure.SignedStructure"/>.
    /// </summary>
    public static BigInteger IssuerHash(MdocDisclosure issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        byte[] digest = System.Security.Cryptography.SHA256.HashData(issuer.SignedStructure);

        return EcdsaNonceRecovery.ToInteger(digest);
    }


    /// <summary>
    /// The committed MACs for the three common values' message halves: <c>mac[i] = (av + ap_i)·m_i</c> over
    /// GF(2^128), six in total (two per value). Exposed so the gate can re-derive them.
    /// </summary>
    public static byte[][] ComputeMacs(byte[][] macMessages)
    {
        ArgumentNullException.ThrowIfNull(macMessages);
        var macs = new byte[6][];
        for(int i = 0; i < 3; i++)
        {
            for(int half = 0; half < 2; half++)
            {
                byte[] m = MessageHalfToGf2k(macMessages[i], half);
                byte[] keyed = new byte[ScalarSize];
                GfAdd(AvKey, ApKeys[(2 * i) + half], keyed, CurveParameterSet.None);
                byte[] mac = new byte[ScalarSize];
                GfMultiply(keyed, m, mac, CurveParameterSet.None);
                macs[(2 * i) + half] = mac;
            }
        }

        return macs;
    }


    /// <summary>
    /// <c>of_bytes_field(msg[half*16 .. +16])</c>: the 16 big-endian message-half bytes read as a GF(2^128)
    /// element (the low 16 bytes little-endian), in the backend's 32-byte canonical-scalar layout. Exposed
    /// so the gate's MAC reconstruction shares the exact convention.
    /// </summary>
    public static byte[] MessageHalfToGf2k(byte[] message, int half)
    {
        ArgumentNullException.ThrowIfNull(message);
        byte[] scalar = new byte[ScalarSize];

        //of_bytes_field reads the 16 bytes little-endian (byte j -> polynomial bit 8*j); the backend stores
        //the element big-endian in the low 16 bytes, so LE byte j maps to canonical[31 - j].
        for(int j = 0; j < Gf2kBytes; j++)
        {
            scalar[ScalarSize - 1 - j] = message[(half * Gf2kBytes) + j];
        }

        return scalar;
    }


    //to_bytes_field(value): the canonical little-endian 32 bytes of the base-field element (the reference's
    //buf for the MAC messages — from_montgomery then to_bytes, fp_generic.h:378-380).
    private static byte[] ToBytesField(BigInteger value)
    {
        byte[] bigEndian = Element(value);
        byte[] littleEndian = new byte[ScalarSize];
        for(int i = 0; i < ScalarSize; i++)
        {
            littleEndian[i] = bigEndian[ScalarSize - 1 - i];
        }

        return littleEndian;
    }


    //fill_gf2k (mac_reference.h:63-68): for bit i in 0..127, push m[i] ? one : zero (LSB-first polynomial
    //bit indexing). m is a GF(2^128) element in the backend's canonical-scalar layout.
    private void FillGf2k(byte[] element)
    {
        for(int i = 0; i < Gf2kBits; i++)
        {
            Push(Gf2kBit(element, i) != 0 ? one : zero);
        }
    }


    //MacWitness::fill_witness (mac_witness.h:38-54): ap_[0], ap_[1], then x_[0], x_[1], each a packed_v128
    //(64 Fp256 elements: the 128 polynomial bits plucked 2 at a time, LSB-first).
    private void FillMacWitness(byte[] ap0, byte[] ap1, byte[] message)
    {
        PushPackedGf2k(ap0);
        PushPackedGf2k(ap1);
        PushPackedGf2k(MessageHalfToGf2k(message, 0));
        PushPackedGf2k(MessageHalfToGf2k(message, 1));
    }


    //pack<packed_v128>(bits, 128) with LOGN=2 (bit_plucker_encoder.h:55-68): r[k] = encode(bits[2k] + 2·bits[2k+1])
    //for k=0..63, where bits[j] is the j-th polynomial coefficient of the GF(2^128) element.
    private void PushPackedGf2k(byte[] element)
    {
        for(int k = 0; k < MacPackedWordElements; k++)
        {
            int v = Gf2kBit(element, 2 * k) + (2 * Gf2kBit(element, (2 * k) + 1));
            Push(pluckerCodes[v]);
        }
    }


    //The j-th polynomial coefficient of a GF(2^128) element in the backend's canonical-scalar layout: the
    //low limb (bits 0..63) sits big-endian in bytes [24,32), the high limb (bits 64..127) in bytes [16,24).
    private static int Gf2kBit(byte[] element, int bit)
    {
        int limbBase = bit < 64 ? 24 : 16;
        int within = bit < 64 ? bit : bit - 64;
        int byteIndex = limbBase + 7 - (within / 8);

        return (element[byteIndex] >> (within % 8)) & 0x1;
    }


    //The four OQ4 2-bit MAC plucker codes encode(v) = subf(of_scalar(2v), of_scalar(N-1)) with N=4
    //(bit_plucker_constants.h:29-31, kMACPluckerBits=2): of_scalar(2v) − of_scalar(3) over Fp256, genuine
    //modular subtraction (NOT the GF XOR of the SHA plucker, and N-1=3 NOT 15).
    private static byte[][] BuildPluckerCodes()
    {
        byte[] ofScalar3 = OfScalarFp256(3);
        var codes = new byte[MacPluckerCount][];
        for(int v = 0; v < MacPluckerCount; v++)
        {
            byte[] code = new byte[ScalarSize];
            FpSubtract(OfScalarFp256((uint)(2 * v)), ofScalar3, code, CurveParameterSet.None);
            codes[v] = code;
        }

        return codes;
    }


    //of_scalar(u) over Fp256: the integer u reduced mod p, canonical big-endian.
    private static byte[] OfScalarFp256(uint value) => Element(new BigInteger(value) % Prime);


    private void AppendColumn(IReadOnlyList<byte[]> elements)
    {
        for(int i = 0; i < elements.Count; i++)
        {
            Push(elements[i]);
        }
    }


    private void Push(byte[] element) => column.Add(element);


    private byte[] Flatten()
    {
        byte[] result = new byte[column.Count * ScalarSize];
        for(int i = 0; i < column.Count; i++)
        {
            column[i].CopyTo(result.AsSpan(i * ScalarSize, ScalarSize));
        }

        return result;
    }


    //A canonical 32-byte big-endian base-field scalar (the library's Scalar form, EcdsaNonceRecovery.Bytes).
    private static byte[] Element(BigInteger value) => EcdsaNonceRecovery.Bytes(value);


    private static BigInteger ToInteger(byte[] bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    //A GF(2^128) constant from 32 hex nibbles read as a 16-byte little-endian polynomial (byte 0 = bits
    //0..7), in the backend's canonical-scalar layout (the element in the low 16 bytes, big-endian).
    private static byte[] Gf2kFromHexLittleEndian(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] scalar = new byte[ScalarSize];
        for(int j = 0; j < Gf2kBytes; j++)
        {
            scalar[ScalarSize - 1 - j] = littleEndian[j];
        }

        return scalar;
    }
}
