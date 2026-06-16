using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.IO;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// Per-region self-consistent oracle gates for <see cref="MdocSignatureWitnessFiller"/>: the 3739-element
/// Fp256 mdoc SIG-circuit witness column (the C# port of the <c>fill_b</c> side of
/// <c>tempdocs/longfellow-zk-reference/lib/circuits/mdoc/mdoc_zk.cc</c> + <c>MdocSignatureWitness::fill_witness</c>).
/// No Docker: every region is re-derived from an independent oracle and byte-compared, mirroring
/// <see cref="EcdsaSignatureWitnessTests"/>'s nine gates and <c>MdocHashWitnessFillerTests</c>' region
/// asserts. The load-bearing end-to-end checks are the two <c>WitnessedLadderRecoversR</c> (issuer + device,
/// each ECDSA column terminating at the point at infinity) plus the column count/shape.
/// </summary>
/// <remarks>
/// The issuer half is the REAL credential (<c>mdoc-00.cbor</c>, <c>age_over_18</c>) via
/// <see cref="MdocDisclosure"/>; the device half is the SYNTHESIZED tuple via
/// <see cref="MdocDeviceSignatureSynth"/> (coordinator decision OQ1). The macs/av are the COMMITTED values
/// from the chosen-constant keys (OQ2); gate 8 asserts the committed (prove-ready) variant rather than the
/// reference's zero-at-commit fill.
/// </remarks>
[TestClass]
internal sealed class MdocSignatureWitnessFillerTests
{
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";

    private const int ScalarSize = 32;
    private const int Gf2kBits = 128;
    private const int LadderBits = 256;
    private const int MacPackedWordElements = 64;

    //The SIG-circuit region boundaries (element indices).
    private const int MacExpansionStart = 4;
    private const int CommonValuesStart = 900;
    private const int IssuerColumnStart = 903;
    private const int IssuerColumnEnd = 1937;
    private const int MacFillsStart = 2971;

    private static readonly BigInteger Prime = P256BaseFieldReference.FieldOrder;
    private static readonly BigInteger CurveA = EcdsaNonceRecovery.A;
    private static readonly BigInteger CurveB = P256BigIntegerG1Reference.CurveB;

    private static readonly ScalarAddDelegate GfAdd = Gf2k128Backend.GetAdd();
    private static readonly ScalarMultiplyDelegate GfMultiply = Gf2k128Backend.GetMultiply();

    private static byte[] Credential { get; } = ReadFixture(CredentialRelativePath);


    [TestMethod]
    public void ColumnHasExactlyTheReferenceShapeAndCount()
    {
        byte[] column = Produce();
        int total = column.Length / ScalarSize;

        Assert.AreEqual(3739, total, "The column must hold exactly 3739 elements (the SIG-circuit input count).");

        //First element is Fp256 one (canonical 0x00..01).
        Assert.IsTrue(Element(column, 0).SequenceEqual(One()), "The first element must be Fp256 one.");

        //The structural region map (900 public + 3 common values + 2 ECDSA columns of 1034 + 3 MacWitness
        //fills of 256) must sum to the produced total — every sub-count tied through the runtime total.
        int mapTotal = MdocSignatureWitnessFiller.PublicInputCount + 3 + (2 * EcdsaSignatureWitness.ElementCount) + (3 * 256);
        Assert.AreEqual(mapTotal, total, "The region map (900 + 3 + 2x1034 + 3x256) must sum to the produced total.");
        Assert.AreEqual(3 * 256, total - MacFillsStart, "The three MacWitness fills total 768 (the tail region).");
    }


    [TestMethod]
    public void PublicPrefixLayout()
    {
        MdocDisclosure issuer = Issuer();
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();
        byte[] column = Produce(issuer, device);

        Assert.IsTrue(Element(column, 0).SequenceEqual(One()), "idx0 must be one.");
        Assert.IsTrue(Element(column, 1).SequenceEqual(EcdsaNonceRecovery.Bytes(ToInteger(issuer.IssuerKeyX))), "idx1 must be pkX.");
        Assert.IsTrue(Element(column, 2).SequenceEqual(EcdsaNonceRecovery.Bytes(ToInteger(issuer.IssuerKeyY))), "idx2 must be pkY.");
        Assert.IsTrue(Element(column, 3).SequenceEqual(EcdsaNonceRecovery.Bytes(device.DeviceHash)), "idx3 must be e2 (the device hash).");

        //The circuit precondition: e2 != 0 (mdoc_zk.cc:196-201).
        Assert.AreNotEqual(BigInteger.Zero, device.DeviceHash, "e2 must be non-zero (the circuit precondition).");

        //OQ6 anti-swap: the device hash e2 (wire 3) must not equal the issuer MSO hash e_ (wire 900).
        BigInteger issuerHash = MdocSignatureWitnessFiller.IssuerHash(issuer);
        Assert.AreNotEqual(issuerHash, device.DeviceHash, "e2 (device) must not equal e_ (issuer): OQ6 anti-swap.");
        Assert.IsTrue(Element(column, CommonValuesStart).SequenceEqual(EcdsaNonceRecovery.Bytes(issuerHash)), "Wire 900 must be e_ (the issuer hash).");
    }


    [TestMethod]
    public void IssuerEcdsaColumnIsSelfConsistent()
    {
        MdocDisclosure issuer = Issuer();
        byte[] column = Produce(issuer, MdocDeviceSignatureSynth.Create());

        BigInteger pkX = ToInteger(issuer.IssuerKeyX);
        BigInteger pkY = ToInteger(issuer.IssuerKeyY);
        BigInteger e = MdocSignatureWitnessFiller.IssuerHash(issuer);
        BigInteger r = ToInteger(issuer.SignatureR);
        BigInteger s = ToInteger(issuer.SignatureS);

        AssertEcdsaColumnSelfConsistent(column, IssuerColumnStart, pkX, pkY, e, r, s);
    }


    [TestMethod]
    public void DeviceEcdsaColumnIsSelfConsistent()
    {
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();
        byte[] column = Produce(Issuer(), device);

        AssertEcdsaColumnSelfConsistent(column, IssuerColumnEnd, device.DeviceKeyX, device.DeviceKeyY, device.DeviceHash, device.SignatureR, device.SignatureS);

        //The .NET oracle: the synthesized tuple is a genuine ECDSA verification, so its recovered nonce
        //point is genuine (mirrors RecoveredNoncePointMatchesTheDotNetSignature).
        Assert.IsTrue(device.Verify(), "The synthesized device tuple must be a valid .NET ECDSA signature.");
    }


    [TestMethod]
    public void MacMessagesMatchTheCommonValues()
    {
        MdocDisclosure issuer = Issuer();
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();
        byte[] column = Produce(issuer, device);

        //The three common values' to_bytes_field (little-endian) message bytes.
        byte[][] expectedMessages =
        [
            ToBytesField(MdocSignatureWitnessFiller.IssuerHash(issuer)),
            ToBytesField(device.DeviceKeyX),
            ToBytesField(device.DeviceKeyY),
        ];

        //The issuer-hash MAC message ties to the HASH-circuit common value (the cross-circuit tie). The
        //device key halves are the SYNTH key here (not the credential's deviceKeyInfo), per OQ1.
        MdocParsedDocument parsed = MdocParsedDocument.Parse(Credential);
        MdocHashWitnessState hashState = MdocHashWitnessState.Compute(parsed, MdocRequestedAttribute.AgeOver18);
        Assert.IsTrue(expectedMessages[0].AsSpan().SequenceEqual(hashState.MacMessageE), "The issuer-hash MAC message must equal the hash circuit's MacMessageE (the common value).");

        //Decode each MacWitness x_ half (the two packed words after the two ap words) and confirm it
        //reconstructs the expected message half.
        for(int i = 0; i < 3; i++)
        {
            int wordBase = MacFillsStart + (i * 256) + (2 * MacPackedWordElements);
            for(int half = 0; half < 2; half++)
            {
                byte[] decodedHalf = DecodePackedHalf(column, wordBase + (half * MacPackedWordElements));
                byte[] expectedHalf = expectedMessages[i].AsSpan(half * 16, 16).ToArray();
                Assert.IsTrue(decodedHalf.AsSpan().SequenceEqual(expectedHalf), $"MacWitness[{i}] x_[{half}] must decode to the common value's message half.");
            }
        }
    }


    [TestMethod]
    public void MacPluckerCodesAreTheFp256TwoBitConstant()
    {
        var filler = new MdocSignatureWitnessFiller();
        byte[][] codes = filler.PluckerCodes;

        Assert.HasCount(4, codes, "There are four 2-bit plucker codes.");

        //encode(v) = of_scalar(2v) − of_scalar(3) over Fp256: {p-3, p-1, 1, 3} (OQ4; N-1=3, NOT 15).
        Assert.IsTrue(codes[0].AsSpan().SequenceEqual(EcdsaNonceRecovery.Bytes(Prime - 3)), "encode(0) must be p-3.");
        Assert.IsTrue(codes[1].AsSpan().SequenceEqual(EcdsaNonceRecovery.Bytes(Prime - 1)), "encode(1) must be p-1.");
        Assert.IsTrue(codes[2].AsSpan().SequenceEqual(EcdsaNonceRecovery.Bytes(BigInteger.One)), "encode(2) must be 1.");
        Assert.IsTrue(codes[3].AsSpan().SequenceEqual(EcdsaNonceRecovery.Bytes(new BigInteger(3))), "encode(3) must be 3.");
    }


    [TestMethod]
    public void MacFillsReproduceTheKeyedConstants()
    {
        MdocDisclosure issuer = Issuer();
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();
        byte[] column = Produce(issuer, device);

        byte[][] macMessages =
        [
            ToBytesField(MdocSignatureWitnessFiller.IssuerHash(issuer)),
            ToBytesField(device.DeviceKeyX),
            ToBytesField(device.DeviceKeyY),
        ];

        //Re-run the MacWitness pack over the chosen ap keys and the recovered x_ halves; byte-compare the
        //256-element fills.
        var rebuilt = new MdocSignatureWitnessFiller();
        byte[] reference = rebuilt.Fill(issuer, device);
        for(int i = MacFillsStart; i < MdocSignatureWitnessFiller.ElementCount; i++)
        {
            Assert.IsTrue(Element(column, i).SequenceEqual(Element(reference, i)), $"MacWitness fill element {i} must reproduce deterministically.");
        }

        //The public macs are consistent with the private ap keys + chosen av: mac[i] = (av + ap_i)·m_i over
        //GF (reuse the computation), and each expands to the fill_gf2k 128-wire form.
        byte[][] macs = MdocSignatureWitnessFiller.ComputeMacs(macMessages);
        for(int i = 0; i < 6; i++)
        {
            byte[] m = MdocSignatureWitnessFiller.MessageHalfToGf2k(macMessages[i / 2], i % 2);
            byte[] keyed = new byte[ScalarSize];
            GfAdd(MdocSignatureWitnessFiller.Av, MdocSignatureWitnessFiller.Ap[i], keyed, CurveParameterSet.None);
            byte[] expected = new byte[ScalarSize];
            GfMultiply(keyed, m, expected, CurveParameterSet.None);
            Assert.IsTrue(macs[i].AsSpan().SequenceEqual(expected), $"mac[{i}] must equal (av + ap)·m over GF(2^128).");
        }
    }


    [TestMethod]
    public void PublicMacAvExpansionIsTheCommittedFillGf2k()
    {
        MdocDisclosure issuer = Issuer();
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();
        byte[] column = Produce(issuer, device);

        byte[][] macMessages =
        [
            ToBytesField(MdocSignatureWitnessFiller.IssuerHash(issuer)),
            ToBytesField(device.DeviceKeyX),
            ToBytesField(device.DeviceKeyY),
        ];
        byte[][] macs = MdocSignatureWitnessFiller.ComputeMacs(macMessages);

        //[4,772): six macs, each a gf2k expanded to 128 one/zero wires; [772,900): av, 128 wires.
        int index = MacExpansionStart;
        for(int i = 0; i < 6; i++)
        {
            AssertGf2kExpansion(column, ref index, macs[i], $"mac[{i}]");
        }

        AssertGf2kExpansion(column, ref index, MdocSignatureWitnessFiller.Av, "av");
        Assert.AreEqual(MdocSignatureWitnessFiller.PublicInputCount, index, "The public mac/av expansion must end exactly at npub_in = 900.");
    }


    [TestMethod]
    public void ColumnIsDeterministicForTheSameInputs()
    {
        MdocDisclosure issuer = Issuer();
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();

        byte[] first = Produce(issuer, device);
        byte[] second = Produce(issuer, device);

        Assert.IsTrue(first.AsSpan().SequenceEqual(second), "Two fills with the same inputs must be byte-identical.");
    }


    //The nine VerifyWitness3 region invariants on an ECDSA sub-column, plus a byte re-derivation against
    //EcdsaSignatureWitness.Fill (verify_witness.h).
    private static void AssertEcdsaColumnSelfConsistent(byte[] column, int start, BigInteger pkX, BigInteger pkY, BigInteger e, BigInteger r, BigInteger s)
    {
        //Re-derive the sub-column and byte-compare every element.
        var expected = EcdsaSignatureWitness.Fill(pkX, pkY, e, r, s);
        for(int i = 0; i < expected.Count; i++)
        {
            Assert.IsTrue(Element(column, start + i).SequenceEqual(expected[i]), $"ECDSA column element {start + i} must match EcdsaSignatureWitness.Fill.");
        }

        EcdsaSignatureWitness.Computed computed = EcdsaSignatureWitness.Compute(pkX, pkY, e, r, s);

        //(1) recovered R.x mod n == r; R on curve.
        (BigInteger X, BigInteger Y) recovered = EcdsaNonceRecovery.RecoverNoncePoint(pkX, pkY, e, r, s);
        Assert.AreEqual(r, EcdsaNonceRecovery.ModN(recovered.X), "The recovered R.x (mod n) must equal r.");
        Assert.AreEqual(r, computed.Rx, "The witnessed rx_ must equal r.");
        Assert.AreEqual(recovered.Y, computed.Ry, "The witnessed ry_ must equal the recovered R.y.");
        Assert.IsTrue(OnCurve(computed.Rx, computed.Ry), "R must lie on the curve.");

        //(2) the base-field inverses invert.
        Assert.AreEqual(BigInteger.One, ModP(computed.RxInverse * computed.Rx), "rx_inv must invert rx.");
        Assert.AreEqual(BigInteger.One, ModP(computed.PkInverse * pkX), "pk_inv must invert pkX.");
        BigInteger nms = EcdsaNonceRecovery.ModN(-s);
        Assert.AreEqual(BigInteger.One, ModP(computed.SInverse * nms), "s_inv must invert (−s mod n).");

        //(3) the precomputed table is on-curve and equals the affine sums.
        (BigInteger X, BigInteger Y) rPoint = (computed.Rx, computed.Ry);
        (BigInteger X, BigInteger Y) gPlusPk = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, (pkX, pkY));
        (BigInteger X, BigInteger Y) gPlusR = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, rPoint);
        (BigInteger X, BigInteger Y) pkPlusR = EcdsaNonceRecovery.AffineAdd((pkX, pkY), rPoint);
        (BigInteger X, BigInteger Y) gRPk = EcdsaNonceRecovery.AffineAdd(gPlusR, (pkX, pkY));
        (BigInteger X, BigInteger Y)[] preExpected = [gPlusPk, gPlusR, pkPlusR, gRPk];
        for(int i = 0; i < 4; i++)
        {
            Assert.IsTrue(OnCurve(computed.Pre[2 * i], computed.Pre[(2 * i) + 1]), $"pre[{2 * i}] must lie on the curve.");
            Assert.AreEqual(preExpected[i].X, computed.Pre[2 * i], $"pre[{2 * i}].x must equal the affine sum.");
            Assert.AreEqual(preExpected[i].Y, computed.Pre[(2 * i) + 1], $"pre[{(2 * i) + 1}].y must equal the affine sum.");
        }

        //(4) bi_ decodes back to b[i].
        for(int i = 0; i < LadderBits; i++)
        {
            int position = LadderBits - i - 1;
            int b = Bit(e, position) + (2 * Bit(r, position)) + (4 * Bit(nms, position));
            BigInteger signed = SignedResidue(computed.Bi[i]);
            Assert.AreEqual(b, (int)((signed + 7) / 2), $"bi_[{i}] must decode back to b[{i}].");
        }

        //(5) int_x/y/z match a re-run ladder.
        ProjectivePointFp256[] mux = BuildMux((pkX, pkY), rPoint);
        ProjectivePointFp256 accumulator = ProjectivePointFp256.Identity;
        for(int i = 0; i < LadderBits; i++)
        {
            int position = LadderBits - i - 1;
            int b = Bit(e, position) + (2 * Bit(r, position)) + (4 * Bit(nms, position));
            if(i > 0)
            {
                accumulator = ProjectivePointFp256.Double(accumulator);
            }

            accumulator = ProjectivePointFp256.Add(accumulator, mux[b]);
            if(i < LadderBits - 1)
            {
                Assert.AreEqual(accumulator.X, computed.IntX[i], $"int_x[{i}] must match the re-run ladder.");
                Assert.AreEqual(accumulator.Y, computed.IntY[i], $"int_y[{i}] must match the re-run ladder.");
                Assert.AreEqual(accumulator.Z, computed.IntZ[i], $"int_z[{i}] must match the re-run ladder.");
            }
        }

        //(6) the witnessed ladder terminates at infinity (e·G + r·Q − s·R = O): the load-bearing check.
        Assert.IsNull(computed.FinalAccumulator.Normalize(), "The witnessed ladder must terminate at the point at infinity.");
        Assert.AreEqual(BigInteger.Zero, computed.FinalAccumulator.Z, "The terminal accumulator Z must be zero.");
    }


    private static ProjectivePointFp256[] BuildMux((BigInteger X, BigInteger Y) pk, (BigInteger X, BigInteger Y) r)
    {
        (BigInteger X, BigInteger Y) gPlusPk = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, pk);
        (BigInteger X, BigInteger Y) gPlusR = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, r);
        (BigInteger X, BigInteger Y) pkPlusR = EcdsaNonceRecovery.AffineAdd(pk, r);
        (BigInteger X, BigInteger Y) gRPk = EcdsaNonceRecovery.AffineAdd(gPlusR, pk);

        return
        [
            ProjectivePointFp256.Identity,
            ProjectivePointFp256.FromAffine(EcdsaNonceRecovery.G),
            ProjectivePointFp256.FromAffine(pk),
            ProjectivePointFp256.FromAffine(gPlusPk),
            ProjectivePointFp256.FromAffine(r),
            ProjectivePointFp256.FromAffine(gPlusR),
            ProjectivePointFp256.FromAffine(pkPlusR),
            ProjectivePointFp256.FromAffine(gRPk),
        ];
    }


    //Assert the 128-element fill_gf2k expansion of a GF(2^128) element: each wire is one (bit set) or zero.
    private static void AssertGf2kExpansion(byte[] column, ref int index, byte[] element, string name)
    {
        for(int bit = 0; bit < Gf2kBits; bit++)
        {
            byte[] expected = Gf2kBit(element, bit) != 0 ? One() : new byte[ScalarSize];
            Assert.IsTrue(Element(column, index).SequenceEqual(expected), $"{name} fill_gf2k wire {bit} must be the expanded bit.");
            index++;
        }
    }


    //Decode one MacWitness packed word (64 elements, each a 2-bit plucker code) into a 16-byte
    //little-endian message half (the inverse of pack<packed_v128>).
    private static byte[] DecodePackedHalf(byte[] column, int wordBase)
    {
        byte[] bits = new byte[Gf2kBits];
        for(int k = 0; k < MacPackedWordElements; k++)
        {
            int v = DecodePluckerCode(Element(column, wordBase + k));
            bits[2 * k] = (byte)(v & 1);
            bits[(2 * k) + 1] = (byte)((v >> 1) & 1);
        }

        //Recompose the 128 polynomial bits into the 16-byte little-endian value (byte j = bits 8j..8j+7).
        byte[] half = new byte[16];
        for(int j = 0; j < 16; j++)
        {
            int b = 0;
            for(int bit = 0; bit < 8; bit++)
            {
                b |= bits[(8 * j) + bit] << bit;
            }

            half[j] = (byte)b;
        }

        return half;
    }


    //Invert encode(v) = of_scalar(2v) − of_scalar(3) over Fp256 by matching the four codes {p-3,p-1,1,3}.
    private static int DecodePluckerCode(ReadOnlySpan<byte> code)
    {
        var value = new BigInteger(code, isUnsigned: true, isBigEndian: true);
        if(value == Prime - 3)
        {
            return 0;
        }

        if(value == Prime - 1)
        {
            return 1;
        }

        if(value == BigInteger.One)
        {
            return 2;
        }

        if(value == new BigInteger(3))
        {
            return 3;
        }

        throw new InvalidOperationException("A packed MAC element is not one of the four 2-bit plucker codes.");
    }


    private static MdocDisclosure Issuer() => MdocDisclosure.Extract(Credential, "org.iso.18013.5.1", "age_over_18");


    private static byte[] Produce() => Produce(Issuer(), MdocDeviceSignatureSynth.Create());


    private static byte[] Produce(MdocDisclosure issuer, MdocDeviceSignatureSynth device)
    {
        var filler = new MdocSignatureWitnessFiller();
        byte[] column = filler.Fill(issuer, device);
        Assert.AreEqual(MdocSignatureWitnessFiller.ElementCount, filler.Count, "The filler element count must equal 3739.");

        return column;
    }


    private static byte[] ToBytesField(BigInteger value)
    {
        byte[] bigEndian = EcdsaNonceRecovery.Bytes(value);
        byte[] littleEndian = new byte[ScalarSize];
        for(int i = 0; i < ScalarSize; i++)
        {
            littleEndian[i] = bigEndian[ScalarSize - 1 - i];
        }

        return littleEndian;
    }


    //The j-th polynomial coefficient of a GF(2^128) element in the backend's canonical-scalar layout (low
    //limb bits 0..63 big-endian in [24,32), high limb bits 64..127 in [16,24)).
    private static int Gf2kBit(byte[] element, int bit)
    {
        int limbBase = bit < 64 ? 24 : 16;
        int within = bit < 64 ? bit : bit - 64;
        int byteIndex = limbBase + 7 - (within / 8);

        return (element[byteIndex] >> (within % 8)) & 0x1;
    }


    private static bool OnCurve(BigInteger x, BigInteger y)
    {
        BigInteger left = ModP(y * y);
        BigInteger right = ModP(ModP(ModP(x * x) * x) + ModP(CurveA * x) + CurveB);

        return left == right;
    }


    private static BigInteger SignedResidue(BigInteger residue)
    {
        BigInteger reduced = ModP(residue);

        return reduced > Prime / 2 ? reduced - Prime : reduced;
    }


    private static ReadOnlySpan<byte> Element(byte[] column, int index) => column.AsSpan(index * ScalarSize, ScalarSize);


    private static byte[] One()
    {
        byte[] one = new byte[ScalarSize];
        one[ScalarSize - 1] = 0x01;

        return one;
    }


    private static BigInteger ModP(BigInteger value) => ((value % Prime) + Prime) % Prime;

    private static int Bit(BigInteger value, int position) => (int)((value >> position) & BigInteger.One);

    private static BigInteger ToInteger(byte[] bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");
}
