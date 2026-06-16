using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Region-by-region byte-oracle gates for <see cref="EcdsaSignatureWitness"/>: the
/// C# port of <c>VerifyWitness3</c>
/// (<c>tempdocs/longfellow-zk-reference/lib/circuits/ecdsa/verify_witness.h</c>).
/// A real P-256/SHA-256 ECDSA triple is produced with the platform
/// <see cref="ECDsa"/>, then every region the circuit's nonce-recovery assertion
/// reads is checked against an independent oracle: the recovered <c>R.x</c> equals
/// the signature <c>r</c> and lies on the curve; the base-field inverses invert;
/// each precomputed-table point is on-curve and equals the affine sum; the
/// <c>bi_</c> encoding decodes back to <c>b[i]</c>; and — the load-bearing
/// end-to-end check — the witnessed double-and-add ladder terminates at the point
/// at infinity, i.e. the column actually proves <c>e·G + r·Q − s·R = O</c>.
/// </summary>
[TestClass]
internal sealed class EcdsaSignatureWitnessTests
{
    private const int ScalarSize = 32;
    private const int LadderBits = 256;

    private static readonly BigInteger Prime = EcdsaNonceRecovery.P;
    private static readonly BigInteger CurveA = EcdsaNonceRecovery.A;
    private static readonly BigInteger CurveB = P256BigIntegerG1Reference.CurveB;

    //A fixed message so the gate is deterministic given a key; the key itself is fixed below.
    private static ReadOnlySpan<byte> Message => "EcdsaSignatureWitness region byte-oracle gate."u8;

    //A deterministic P-256 private key (a fixed in-range scalar d), so the whole column is reproducible —
    //no ECDsa.Create()-generated key, no System.Random, no time. d is well below n.
    private const string PrivateKeyHex = "00112233445566778899aabbccddeeff0123456789abcdef0011223344556677";


    [TestMethod]
    public void RecoveredRxEqualsSignatureRAndLiesOnCurve()
    {
        Triple triple = SampleTriple();
        EcdsaSignatureWitness.Computed computed = EcdsaSignatureWitness.Compute(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //The recovered nonce point R = (e/s)·G + (r/s)·Q, recomputed independently of the filler.
        (BigInteger X, BigInteger Y) recovered = EcdsaNonceRecovery.RecoverNoncePoint(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //verify_witness.h:74,92 — rx_ is set to r (the signature), trusted to equal the recovered R.x. For a
        //valid signature the recovered x reduces mod n to r; pin that the recovery genuinely produces r, not an echo.
        Assert.AreEqual(triple.R, EcdsaNonceRecovery.ModN(recovered.X), "The recovered R.x (mod n) must equal the signature r.");
        Assert.AreEqual(triple.R, computed.Rx, "The witnessed rx_ must equal the signature r (rx < n < p, so canonical mod p is r).");
        Assert.AreEqual(recovered.Y, computed.Ry, "The witnessed ry_ must equal the recovered R.y.");
        Assert.IsTrue(OnCurve(computed.Rx, computed.Ry), "The recovered nonce point R must lie on the curve.");
    }


    [TestMethod]
    public void BaseFieldInversesInvert()
    {
        Triple triple = SampleTriple();
        EcdsaSignatureWitness.Computed computed = EcdsaSignatureWitness.Compute(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //verify_witness.h:96-99 — rx_inv·rx == 1 (mod p).
        Assert.AreEqual(BigInteger.One, ModP(computed.RxInverse * computed.Rx), "rx_inv must invert rx in the base field.");

        //verify_witness.h:106-108 — pk_inv·pkX == 1 (mod p).
        Assert.AreEqual(BigInteger.One, ModP(computed.PkInverse * triple.PkX), "pk_inv must invert pkX in the base field.");

        //verify_witness.h:101-104 — s_inv is the integer nms = (−s) mod n reinterpreted in Fp, then inverted in Fp.
        BigInteger nms = EcdsaNonceRecovery.ModN(-triple.S);
        Assert.AreEqual(BigInteger.One, ModP(computed.SInverse * nms), "s_inv must invert (−s mod n) in the base field.");
    }


    [TestMethod]
    public void PrecomputedTablePointsAreOnCurveAndEqualTheAffineSums()
    {
        Triple triple = SampleTriple();
        EcdsaSignatureWitness.Computed computed = EcdsaSignatureWitness.Compute(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //verify_witness.h:112-138 — pre[0,1]=g+pk; pre[2,3]=g+R; pre[4,5]=pk+R; pre[6,7]=g+r+pk.
        (BigInteger X, BigInteger Y) r = (computed.Rx, computed.Ry);
        (BigInteger X, BigInteger Y) gPlusPk = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, (triple.PkX, triple.PkY));
        (BigInteger X, BigInteger Y) gPlusR = EcdsaNonceRecovery.AffineAdd(EcdsaNonceRecovery.G, r);
        (BigInteger X, BigInteger Y) pkPlusR = EcdsaNonceRecovery.AffineAdd((triple.PkX, triple.PkY), r);
        (BigInteger X, BigInteger Y) gRPk = EcdsaNonceRecovery.AffineAdd(gPlusR, (triple.PkX, triple.PkY));

        (BigInteger X, BigInteger Y)[] expected = [gPlusPk, gPlusR, pkPlusR, gRPk];
        for(int i = 0; i < 4; i++)
        {
            BigInteger x = computed.Pre[2 * i];
            BigInteger y = computed.Pre[(2 * i) + 1];
            Assert.IsTrue(OnCurve(x, y), $"Precomputed point pre[{2 * i}] must lie on the curve.");
            Assert.AreEqual(expected[i].X, x, $"pre[{2 * i}].x must equal the affine sum.");
            Assert.AreEqual(expected[i].Y, y, $"pre[{(2 * i) + 1}].y must equal the affine sum.");
        }
    }


    [TestMethod]
    public void BiEncodingDecodesBackToTheLadderDigit()
    {
        Triple triple = SampleTriple();
        EcdsaSignatureWitness.Computed computed = EcdsaSignatureWitness.Compute(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //verify_witness.h:148-152 — b[i] = e.bit + 2·r.bit + 4·nms.bit; bi_[i] = of_scalar(2·b[i]) − of_scalar(7).
        //Inverting: b[i] = (bi_[i] + 7) / 2 with bi_[i] taken as the signed residue in [−7, 7].
        BigInteger nms = EcdsaNonceRecovery.ModN(-triple.S);
        for(int i = 0; i < LadderBits; i++)
        {
            int position = LadderBits - i - 1;
            int b = Bit(triple.E, position) + (2 * Bit(triple.R, position)) + (4 * Bit(nms, position));

            BigInteger signed = SignedResidue(computed.Bi[i]);
            Assert.IsTrue(signed >= -7 && signed <= 7, $"bi_[{i}] must be a signed digit in [−7, 7].");
            Assert.AreEqual(b, (int)((signed + 7) / 2), $"bi_[{i}] must decode back to b[{i}].");
            Assert.AreEqual(BigInteger.Zero, (signed + 7) % 2, $"bi_[{i}] must have even (bi+7), i.e. encode an integer digit.");
        }
    }


    [TestMethod]
    public void WitnessedLadderRecoversR()
    {
        Triple triple = SampleTriple();
        EcdsaSignatureWitness.Computed computed = EcdsaSignatureWitness.Compute(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //verify_witness.h:189-196 — after the final (i = 255) step the accumulator is the identity:
        //e·G + r·Q − s·R = O. This is the assertion the circuit checks; the stored int_x/y/z drive it.
        Assert.IsNull(computed.FinalAccumulator.Normalize(),
            "The witnessed double-and-add ladder must terminate at the point at infinity (the nonce-recovery identity holds).");

        //The last EMITTED intermediate is int at i = 254 (verify_witness.h:64: emit only for i < kBits-1);
        //doubling it then adding the i = 255 muxed point must reach that terminal identity. The filler already
        //performs exactly this, so the final accumulator above being O is the end-to-end witness check.
        Assert.AreEqual(BigInteger.Zero, computed.FinalAccumulator.X, "The terminal accumulator X must be zero.");
        Assert.AreEqual(BigInteger.Zero, computed.FinalAccumulator.Z, "The terminal accumulator Z must be zero (identity).");
    }


    [TestMethod]
    public void IntermediateLadderPointsAreConsistentWithReRunningTheLadder()
    {
        Triple triple = SampleTriple();
        EcdsaSignatureWitness.Computed computed = EcdsaSignatureWitness.Compute(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //Independently re-run the muxed projective ladder and confirm the stored int_x/y/z at every emitted
        //index (i = 0..254) match, pinning the store-AFTER-double-and-add order (verify_witness.h:154-186).
        BigInteger nms = EcdsaNonceRecovery.ModN(-triple.S);
        (BigInteger X, BigInteger Y) r = (computed.Rx, computed.Ry);
        ProjectivePointFp256[] mux = BuildMux(triple, r);

        ProjectivePointFp256 accumulator = ProjectivePointFp256.Identity;
        for(int i = 0; i < LadderBits; i++)
        {
            int position = LadderBits - i - 1;
            int b = Bit(triple.E, position) + (2 * Bit(triple.R, position)) + (4 * Bit(nms, position));

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
    }


    [TestMethod]
    public void ColumnHasExactlyTheReferenceElementCountAndShape()
    {
        Triple triple = SampleTriple();
        var column = EcdsaSignatureWitness.Fill(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        //5 + 8 + 256 + 3·255 = 1034 (verify_witness.h:53-70).
        Assert.HasCount(EcdsaSignatureWitness.ElementCount, column, "The filled column must hold exactly 1034 elements.");
        Assert.HasCount(1034, column, "The 1034-element total is the reference's VerifyWitness3 column size.");
        foreach(byte[] element in column)
        {
            Assert.HasCount(ScalarSize, element, "Every element is a canonical 32-byte scalar.");
        }
    }


    [TestMethod]
    public void ColumnIsDeterministicForTheSameTriple()
    {
        Triple triple = SampleTriple();
        var first = EcdsaSignatureWitness.Fill(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);
        var second = EcdsaSignatureWitness.Fill(triple.PkX, triple.PkY, triple.E, triple.R, triple.S);

        Assert.HasCount(EcdsaSignatureWitness.ElementCount, first, "The first fill must produce the full column.");
        Assert.HasCount(EcdsaSignatureWitness.ElementCount, second, "The second fill must produce the full column.");
        for(int i = 0; i < first.Count; i++)
        {
            CollectionAssert.AreEqual(first[i], second[i], $"Element {i} must be identical across fills.");
        }
    }


    [TestMethod]
    public void RecoveredNoncePointMatchesTheDotNetSignature()
    {
        //An independent oracle: the .NET-produced signature verifies, so the R our filler recovers is the
        //genuine nonce point. (.NET's verifier recomputes R = (e/s)G + (r/s)Q and checks R.x == r mod n.)
        using ECDsa ecdsa = CreateKey();
        Triple triple = SampleTriple(ecdsa);

        Span<byte> signature = stackalloc byte[2 * ScalarSize];
        EcdsaNonceRecovery.Bytes(triple.R).CopyTo(signature[..ScalarSize]);
        EcdsaNonceRecovery.Bytes(triple.S).CopyTo(signature[ScalarSize..]);

        Assert.IsTrue(
            ecdsa.VerifyData(Message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            "The sampled triple must be a valid .NET ECDSA signature, so the recovered nonce point is genuine.");
    }


    private static ProjectivePointFp256[] BuildMux(Triple triple, (BigInteger X, BigInteger Y) r)
    {
        (BigInteger X, BigInteger Y) pk = (triple.PkX, triple.PkY);
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


    //A deterministic, valid P-256 ECDSA triple (pkX, pkY, e, r, s) from the fixed key over the fixed message.
    private static Triple SampleTriple()
    {
        using ECDsa ecdsa = CreateKey();

        return SampleTriple(ecdsa);
    }


    private static Triple SampleTriple(ECDsa ecdsa)
    {
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        BigInteger pkX = ToInteger(parameters.Q.X!);
        BigInteger pkY = ToInteger(parameters.Q.Y!);

        Span<byte> signature = stackalloc byte[2 * ScalarSize];
        ecdsa.SignData(Message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        BigInteger r = EcdsaNonceRecovery.ToInteger(signature[..ScalarSize]);
        BigInteger s = EcdsaNonceRecovery.ToInteger(signature[ScalarSize..]);

        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(Message, digest);
        BigInteger e = EcdsaNonceRecovery.ToInteger(digest);

        return new Triple(pkX, pkY, e, r, s);
    }


    private static ECDsa CreateKey()
    {
        byte[] d = Convert.FromHexString(PrivateKeyHex);
        ECParameters parameters = new()
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
        };

        //Derive the public point Q = d·G via the reference, so the imported key is complete and deterministic.
        (BigInteger X, BigInteger Y) q = EcdsaNonceRecovery.ScalarMultiply(EcdsaNonceRecovery.ToInteger(d), EcdsaNonceRecovery.G);
        parameters.Q = new ECPoint
        {
            X = EcdsaNonceRecovery.Bytes(q.X),
            Y = EcdsaNonceRecovery.Bytes(q.Y),
        };

        return ECDsa.Create(parameters);
    }


    private static bool OnCurve(BigInteger x, BigInteger y)
    {
        //y² == x³ + a·x + b (mod p).
        BigInteger left = ModP(y * y);
        BigInteger right = ModP(ModP(ModP(x * x) * x) + ModP(CurveA * x) + CurveB);

        return left == right;
    }


    //The signed representative of a base-field residue in (−p/2, p/2], so the (−7..7) bi_ encoding reads back.
    private static BigInteger SignedResidue(BigInteger residue)
    {
        BigInteger reduced = ModP(residue);

        return reduced > Prime / 2 ? reduced - Prime : reduced;
    }


    private static BigInteger ModP(BigInteger value) => ((value % Prime) + Prime) % Prime;

    private static int Bit(BigInteger value, int position) => (int)((value >> position) & BigInteger.One);

    private static BigInteger ToInteger(byte[] bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private readonly record struct Triple(BigInteger PkX, BigInteger PkY, BigInteger E, BigInteger R, BigInteger S);
}
