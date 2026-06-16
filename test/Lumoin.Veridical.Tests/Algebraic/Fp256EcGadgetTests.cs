using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// First atom of the Longfellow-style ECDSA-verification gadget (LF.5): elliptic
/// curve point addition expressed as hand-built Ligero linear + quadratic
/// constraints over the P-256 <em>base</em> field <c>Fp256</c> (the field
/// Longfellow's ECDSA circuit runs in), proven with the LF.4b
/// <see cref="LigeroProver"/> and verified with <see cref="LigeroVerifier"/>.
/// </summary>
/// <remarks>
/// <para>
/// The affine group law for <c>P + Q = R</c> (generic case, <c>P ≠ ±Q</c>) is
/// the slope identity used by <see cref="P256BigIntegerG1Reference"/>:
/// <c>λ = (y2 − y1)/(x2 − x1)</c>, <c>x3 = λ² − x1 − x2</c>,
/// <c>y3 = λ(x1 − x3) − y1</c>. In R1CS form every multiplication becomes one
/// quadratic constraint <c>W[z] = W[x]·W[y]</c> with the linear relations carried
/// by linear constraints — three quadratics total. The proof attests the
/// witnessed output is the true sum; the test additionally gates the witnessed
/// sum against the reference backend (compressed-point equality).
/// </para>
/// <para>
/// This is the building block the witnessed double-and-add ladder, the 8-point
/// table and the Alg.4 identity <c>id = G·e + Q·r − R·s</c> compose from. It is a
/// correctness spike over the NTT-free barycentric encoder; on-curve checks,
/// doubling, and the full ladder are subsequent atoms.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Fp256EcGadgetTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int CompressedSize = 33;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private static readonly BigInteger P = P256BigIntegerG1Reference.BaseFieldPrime;
    private static readonly BigInteger A = P256BigIntegerG1Reference.CurveA;
    private static readonly BigInteger B = P256BigIntegerG1Reference.CurveB;

    //The curve constants a, b as canonical Fp256 bytes for the Core gadget layer.
    private static readonly byte[] CurveABytes = ToCanonical(A);
    private static readonly byte[] CurveBBytes = ToCanonical(B);

    //The standard P-256 base point (FIPS 186-4 / SEC2 secp256r1).
    private static readonly BigInteger GeneratorX = BigInteger.Parse(
        "06b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    private static readonly BigInteger GeneratorY = BigInteger.Parse(
        "04fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    //A fixed valid nonce in [1, n−1] for the full-scale Alg.4 oracle gate (matches
    //the reference ECDSA tests). Nonce reuse is forbidden in production; a fixed
    //one is fine for gating arithmetic against the reference.
    private const string NonceHex = "1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00";

    private static readonly byte[] TranscriptSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ec-add.v1");
    private static readonly byte[] RandomnessSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ec-add.rng.v1");

    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;


    [TestMethod]
    public void PointAdditionGadgetVerifiesAndMatchesTheReference()
    {
        //A = 3·G, B = 5·G, so the witnessed sum must be C = 8·G.
        (BigInteger ax, BigInteger ay) = ScalarMul(3, (GeneratorX, GeneratorY));
        (BigInteger bx, BigInteger by) = ScalarMul(5, (GeneratorX, GeneratorY));
        (BigInteger cx, BigInteger cy) = AffineAdd((ax, ay), (bx, by));

        //Gate the test arithmetic against the reference backend: the reference's
        //compressed A+B must equal our compressed C.
        Span<byte> referenceSum = stackalloc byte[CompressedSize];
        P256BigIntegerG1Reference.GetAdd()(Encode(ax, ay), Encode(bx, by), referenceSum, CurveParameterSet.None);
        Assert.IsTrue(referenceSum.SequenceEqual(Encode(cx, cy)), "Reference A+B must match the test arithmetic (gate).");

        var (builder, ec) = NewGadget();
        int x1 = Wire(builder, ax), y1 = Wire(builder, ay), x2 = Wire(builder, bx), y2 = Wire(builder, by);
        (int x3, int y3) = builder.AddAffinePointAddition(ec, x1, y1, x2, y2);

        Assert.AreEqual(cx, Val(builder, x3), "Gadget x3 must equal the reference sum x.");
        Assert.AreEqual(cy, Val(builder, y3), "Gadget y3 must equal the reference sum y.");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "An honest point-addition proof over Fp256 must verify.");
    }


    [TestMethod]
    public void TamperedPointAdditionProofIsRejected()
    {
        (BigInteger ax, BigInteger ay) = ScalarMul(7, (GeneratorX, GeneratorY));
        (BigInteger bx, BigInteger by) = ScalarMul(11, (GeneratorX, GeneratorY));

        var (builder, ec) = NewGadget();
        int x1 = Wire(builder, ax), y1 = Wire(builder, ay), x2 = Wire(builder, bx), y2 = Wire(builder, by);
        builder.AddAffinePointAddition(ec, x1, y1, x2, y2);

        using LigeroProof proof = ProveGadget(builder);
        proof.OpenedColumnMutable(0)[0] ^= 0x01;

        Assert.IsFalse(VerifyGadget(builder, proof, TranscriptSeed), "A tampered point-addition proof must be rejected.");
    }


    [TestMethod]
    public void InconsistentSumCannotBeProven()
    {
        //A witness claiming a wrong sum (x3,y3 not satisfying the group law) must
        //be unprovable: the slope/output quadratic constraints are violated, so
        //the prover refuses.
        (BigInteger ax, BigInteger ay) = ScalarMul(2, (GeneratorX, GeneratorY));
        (BigInteger bx, BigInteger by) = ScalarMul(6, (GeneratorX, GeneratorY));

        var (builder, ec) = NewGadget();
        int x1 = Wire(builder, ax), y1 = Wire(builder, ay), x2 = Wire(builder, bx), y2 = Wire(builder, by);
        builder.AddAffinePointAddition(ec, x1, y1, x2, y2);
        builder.CorruptLastOutputForTesting();

        Assert.ThrowsExactly<InvalidOperationException>(() => ProveGadget(builder).Dispose());
    }


    [TestMethod]
    public void PointDoublingGadgetVerifiesAndMatchesTheReference()
    {
        //A = 5·G, so the witnessed double must be 2A = 10·G.
        (BigInteger ax, BigInteger ay) = ScalarMul(5, (GeneratorX, GeneratorY));
        (BigInteger cx, BigInteger cy) = AffineDouble((ax, ay));

        //Gate: the reference's [2]·A must equal our compressed double.
        Span<byte> referenceDouble = stackalloc byte[CompressedSize];
        Span<byte> two = stackalloc byte[ScalarSize];
        WriteCanonical(2, two);
        P256BigIntegerG1Reference.GetScalarMultiply()(Encode(ax, ay), two, referenceDouble, CurveParameterSet.None);
        Assert.IsTrue(referenceDouble.SequenceEqual(Encode(cx, cy)), "Reference [2]·A must match the test arithmetic (gate).");

        var (builder, ec) = NewGadget();
        int x = Wire(builder, ax), y = Wire(builder, ay);
        (int x3, int y3) = builder.AddAffinePointDoubling(ec, x, y);

        Assert.AreEqual(cx, Val(builder, x3), "Gadget doubled x must equal the reference.");
        Assert.AreEqual(cy, Val(builder, y3), "Gadget doubled y must equal the reference.");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "An honest point-doubling proof over Fp256 must verify.");
    }


    [TestMethod]
    public void OnCurveCheckVerifiesForAValidPoint()
    {
        (BigInteger ax, BigInteger ay) = ScalarMul(9, (GeneratorX, GeneratorY));

        var (builder, ec) = NewGadget();
        int x = Wire(builder, ax), y = Wire(builder, ay);
        builder.AddOnCurveCheck(ec, x, y);

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "An on-curve point must satisfy the curve-equation gadget.");
    }


    [TestMethod]
    public void OffCurvePointCannotBeProven()
    {
        //Perturb y off the curve: y² = x³ + ax + b no longer holds, so the
        //curve-equation constraint is unsatisfied and the prover refuses.
        (BigInteger ax, BigInteger ay) = ScalarMul(9, (GeneratorX, GeneratorY));

        var (builder, ec) = NewGadget();
        int x = Wire(builder, ax), y = Wire(builder, ay + BigInteger.One);
        builder.AddOnCurveCheck(ec, x, y);

        Assert.ThrowsExactly<InvalidOperationException>(() => ProveGadget(builder).Dispose());
    }


    [TestMethod]
    public void CompleteAdditionMatchesTheReferenceForDistinctPoints()
    {
        (BigInteger ax, BigInteger ay) = ScalarMul(3, (GeneratorX, GeneratorY));
        (BigInteger bx, BigInteger by) = ScalarMul(5, (GeneratorX, GeneratorY));
        (BigInteger cx, BigInteger cy) = AffineAdd((ax, ay), (bx, by));

        Span<byte> reference = stackalloc byte[CompressedSize];
        P256BigIntegerG1Reference.GetAdd()(Encode(ax, ay), Encode(bx, by), reference, CurveParameterSet.None);
        Assert.IsTrue(reference.SequenceEqual(Encode(cx, cy)), "Reference A+B must match the test arithmetic (gate).");

        var (builder, ec) = NewGadget();
        (int x3, int y3, int z3) = AddProjective(builder, ec, ax, ay, BigInteger.One, bx, by, BigInteger.One);

        (BigInteger X, BigInteger Y)? affine = Normalize(Val(builder, x3), Val(builder, y3), Val(builder, z3));
        Assert.IsNotNull(affine);
        Assert.AreEqual(cx, affine!.Value.X, "Complete-addition x must match the reference sum.");
        Assert.AreEqual(cy, affine.Value.Y, "Complete-addition y must match the reference sum.");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "An honest complete-addition proof over Fp256 must verify.");
    }


    [TestMethod]
    public void CompleteAdditionWithIdentityReturnsThePoint()
    {
        //A + O = A. O is the projective point (0:1:0).
        (BigInteger ax, BigInteger ay) = ScalarMul(4, (GeneratorX, GeneratorY));

        var (builder, ec) = NewGadget();
        (int x3, int y3, int z3) = AddProjective(builder, ec, ax, ay, BigInteger.One, BigInteger.Zero, BigInteger.One, BigInteger.Zero);

        (BigInteger X, BigInteger Y)? affine = Normalize(Val(builder, x3), Val(builder, y3), Val(builder, z3));
        Assert.IsNotNull(affine);
        Assert.AreEqual(ax, affine!.Value.X, "A + O must normalize to A (x).");
        Assert.AreEqual(ay, affine.Value.Y, "A + O must normalize to A (y).");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "A + O must verify under the complete formula.");
    }


    [TestMethod]
    public void CompleteAdditionOfInversesIsTheIdentity()
    {
        //A + (−A) = O: the result is the projective identity, i.e. Z3 = 0.
        (BigInteger ax, BigInteger ay) = ScalarMul(6, (GeneratorX, GeneratorY));

        var (builder, ec) = NewGadget();
        (int x3, int y3, int z3) = AddProjective(builder, ec, ax, ay, BigInteger.One, ax, Mod(-ay), BigInteger.One);

        Assert.AreEqual(BigInteger.Zero, Val(builder, z3), "A + (−A) must give the identity (Z3 = 0).");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "A + (−A) = O must verify under the complete formula.");
    }


    [TestMethod]
    public void CompleteAdditionOfEqualPointsDoubles()
    {
        //A + A = 2A: the complete formula handles the doubling case unconditionally.
        (BigInteger ax, BigInteger ay) = ScalarMul(3, (GeneratorX, GeneratorY));
        (BigInteger dx, BigInteger dy) = AffineDouble((ax, ay));

        var (builder, ec) = NewGadget();
        (int x3, int y3, int z3) = AddProjective(builder, ec, ax, ay, BigInteger.One, ax, ay, BigInteger.One);

        (BigInteger X, BigInteger Y)? affine = Normalize(Val(builder, x3), Val(builder, y3), Val(builder, z3));
        Assert.IsNotNull(affine);
        Assert.AreEqual(dx, affine!.Value.X, "A + A must normalize to 2A (x).");
        Assert.AreEqual(dy, affine.Value.Y, "A + A must normalize to 2A (y).");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "A + A = 2A must verify under the complete formula.");
    }


    [TestMethod]
    public void ChainedCompleteAdditionSpansWitnessRowsAndMatchesReference()
    {
        //(A + B) + C with A=2G, B=3G, C=5G ⇒ 10·G. Two complete additions push the
        //witness past one Ligero row (w = block − nreq), exercising the
        //multi-witness-row path the full ladder relies on.
        (BigInteger ax, BigInteger ay) = ScalarMul(2, (GeneratorX, GeneratorY));
        (BigInteger bx, BigInteger by) = ScalarMul(3, (GeneratorX, GeneratorY));
        (BigInteger cx, BigInteger cy) = ScalarMul(5, (GeneratorX, GeneratorY));
        (BigInteger ex, BigInteger ey) = AffineAdd(AffineAdd((ax, ay), (bx, by)), (cx, cy));

        Span<byte> reference = stackalloc byte[CompressedSize];
        Span<byte> ten = stackalloc byte[ScalarSize];
        WriteCanonical(10, ten);
        P256BigIntegerG1Reference.GetScalarMultiply()(Encode(GeneratorX, GeneratorY), ten, reference, CurveParameterSet.None);
        Assert.IsTrue(reference.SequenceEqual(Encode(ex, ey)), "Reference 10·G must match (A+B)+C (gate).");

        var (builder, ec) = NewGadget();
        int ax1 = Wire(builder, ax), ay1 = Wire(builder, ay), az1 = Wire(builder, BigInteger.One);
        int bx1 = Wire(builder, bx), by1 = Wire(builder, by), bz1 = Wire(builder, BigInteger.One);
        int cx1 = Wire(builder, cx), cy1 = Wire(builder, cy), cz1 = Wire(builder, BigInteger.One);

        (int X3, int Y3, int Z3) sum1 = builder.AddCompleteProjectiveAddition(ec, ax1, ay1, az1, bx1, by1, bz1);
        (int X3, int Y3, int Z3) sum2 = builder.AddCompleteProjectiveAddition(ec, sum1.X3, sum1.Y3, sum1.Z3, cx1, cy1, cz1);

        (BigInteger X, BigInteger Y)? affine = Normalize(Val(builder, sum2.X3), Val(builder, sum2.Y3), Val(builder, sum2.Z3));
        Assert.IsNotNull(affine);
        Assert.AreEqual(ex, affine!.Value.X, "(A+B)+C must normalize to 10·G (x).");
        Assert.AreEqual(ey, affine.Value.Y, "(A+B)+C must normalize to 10·G (y).");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "A chained two-addition proof spanning witness rows must verify.");
    }


    [TestMethod]
    public void SingleScalarLadderMatchesTheReference()
    {
        //[k]·G via the witnessed double-and-add ladder, gated against the reference
        //scalar multiply. A small scalar keeps the O(n²) barycentric encoder fast;
        //the per-bit structure is identical at full width.
        const int k = 13;
        const int width = 5;
        (BigInteger kx, BigInteger ky) = ScalarMul(k, (GeneratorX, GeneratorY));

        Span<byte> reference = stackalloc byte[CompressedSize];
        Span<byte> scalar = stackalloc byte[ScalarSize];
        WriteCanonical(k, scalar);
        P256BigIntegerG1Reference.GetScalarMultiply()(Encode(GeneratorX, GeneratorY), scalar, reference, CurveParameterSet.None);
        Assert.IsTrue(reference.SequenceEqual(Encode(kx, ky)), "Reference [k]·G must match the test arithmetic (gate).");

        var (builder, ec) = NewGadget();
        int px = Wire(builder, GeneratorX), py = Wire(builder, GeneratorY), pz = Const(builder, BigInteger.One);
        int[] bitsMsbFirst = AddScalarBits(builder, k, width);

        //Recomposition binds the bits to the scalar value (mod n ≡ integer here).
        int[] bitsLsbFirst = (int[])bitsMsbFirst.Clone();
        Array.Reverse(bitsLsbFirst);
        int recomposed = builder.AddRecomposedScalar(bitsLsbFirst);
        Assert.AreEqual((BigInteger)k, Val(builder, recomposed), "Recomposed scalar must equal k.");

        (int X, int Y, int Z) result = builder.AddScalarMultiplyLadder(ec, bitsMsbFirst, px, py, pz);

        (BigInteger X, BigInteger Y)? affine = Normalize(Val(builder, result.X), Val(builder, result.Y), Val(builder, result.Z));
        Assert.IsNotNull(affine);
        Assert.AreEqual(kx, affine!.Value.X, "Ladder [k]·G must match the reference (x).");
        Assert.AreEqual(ky, affine.Value.Y, "Ladder [k]·G must match the reference (y).");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "An honest single-scalar ladder proof over Fp256 must verify.");
    }


    [TestMethod]
    public void NonBooleanScalarBitCannotBeProven()
    {
        //A bit wire carrying 2 violates b² = b, so the boolean constraint is
        //unsatisfied and the prover refuses — the guard against a malicious witness
        //smuggling a non-bit into the ladder's recomposition.
        var (builder, _) = NewGadget();
        Span<byte> two = stackalloc byte[ScalarSize];
        WriteCanonical(BigInteger.One + BigInteger.One, two);
        builder.AddBit(two);

        Assert.ThrowsExactly<InvalidOperationException>(() => ProveGadget(builder).Dispose());
    }


    [TestMethod]
    public void ThreeScalarMultiScalarMultiplyMatchesTheReference()
    {
        //Straus/Shamir MSM [a0]·P0 + [a1]·P1 + [a2]·P2 with P0=G, P1=2G, P2=3G and
        //(a0,a1,a2)=(3,2,1), so the result is (3·1 + 2·2 + 1·3)·G = 10·G. Using
        //multiples of G keeps the gate a single reference scalar multiply while the
        //8-point table, per-step 3-bit selection, and double-add all exercise.
        const int width = 2;
        (BigInteger p1x, BigInteger p1y) = ScalarMul(2, (GeneratorX, GeneratorY));
        (BigInteger p2x, BigInteger p2y) = ScalarMul(3, (GeneratorX, GeneratorY));
        (BigInteger ex, BigInteger ey) = ScalarMul(10, (GeneratorX, GeneratorY));

        Span<byte> reference = stackalloc byte[CompressedSize];
        Span<byte> ten = stackalloc byte[ScalarSize];
        WriteCanonical(10, ten);
        P256BigIntegerG1Reference.GetScalarMultiply()(Encode(GeneratorX, GeneratorY), ten, reference, CurveParameterSet.None);
        Assert.IsTrue(reference.SequenceEqual(Encode(ex, ey)), "Reference 10·G must match the MSM result (gate).");

        var (builder, ec) = NewGadget();
        (int X, int Y, int Z) p0 = (Wire(builder, GeneratorX), Wire(builder, GeneratorY), Const(builder, BigInteger.One));
        (int X, int Y, int Z) p1 = (Wire(builder, p1x), Wire(builder, p1y), Const(builder, BigInteger.One));
        (int X, int Y, int Z) p2 = (Wire(builder, p2x), Wire(builder, p2y), Const(builder, BigInteger.One));

        int[] a0 = AddScalarBits(builder, 3, width);
        int[] a1 = AddScalarBits(builder, 2, width);
        int[] a2 = AddScalarBits(builder, 1, width);

        (int X, int Y, int Z) result = builder.AddThreeScalarMultiScalarMultiply(ec, p0, p1, p2, a0, a1, a2);

        (BigInteger X, BigInteger Y)? affine = Normalize(Val(builder, result.X), Val(builder, result.Y), Val(builder, result.Z));
        Assert.IsNotNull(affine);
        Assert.AreEqual(ex, affine!.Value.X, "MSM result must match 10·G (x).");
        Assert.AreEqual(ey, affine.Value.Y, "MSM result must match 10·G (y).");

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "An honest three-scalar MSM proof over Fp256 must verify.");
    }


    [TestMethod]
    public void Alg4IdentityHoldsForARealP256SignatureAtFullScale()
    {
        //The Longfellow reformulation (Alg.4): a valid ECDSA signature satisfies
        //e·G + r·Q − s·R = O, where R = k·G is the nonce point, Q = d·G the public
        //key, and r = R.x mod n. This avoids the mod-n inverse the textbook verify
        //(R = (e/s)·G + (r/s)·Q) needs — multiply that through by s. Checked at full
        //256-bit scale: e, r, s are all full-size, gated against the reference.
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        Span<byte> privateKey = stackalloc byte[ScalarSize];
        LeftPad(parameters.D, privateKey);
        BigInteger d = new(privateKey, isUnsigned: true, isBigEndian: true);

        ReadOnlySpan<byte> message = "Longfellow Alg.4 identity over a real P-256 signature."u8;
        Span<byte> digest = stackalloc byte[ScalarSize];
        SHA256.HashData(message, digest);
        BigInteger e = ModOrder(new BigInteger(digest, isUnsigned: true, isBigEndian: true));

        BigInteger k = new(Convert.FromHexString(NonceHex), isUnsigned: true, isBigEndian: true);

        //Q = d·G and R = k·G from the identity-aware oracle; r = R.x mod n.
        (BigInteger X, BigInteger Y) publicPoint = OracleScalarMultiply(d, (GeneratorX, GeneratorY))!.Value;
        (BigInteger X, BigInteger Y) noncePoint = OracleScalarMultiply(k, (GeneratorX, GeneratorY))!.Value;
        BigInteger r = ModOrder(noncePoint.X);

        //The reference produces s and gates Q: its compressed key must round-trip.
        Span<byte> nonce = stackalloc byte[ScalarSize];
        Convert.FromHexString(NonceHex).CopyTo(nonce);
        Span<byte> rBytes = stackalloc byte[ScalarSize];
        Span<byte> sBytes = stackalloc byte[ScalarSize];
        P256EcdsaReference.Sign(privateKey, digest, nonce, rBytes, sBytes);
        BigInteger s = new(sBytes, isUnsigned: true, isBigEndian: true);
        Assert.AreEqual(r, new BigInteger(rBytes, isUnsigned: true, isBigEndian: true), "Reference r must equal R.x mod n.");

        byte[] publicKey = Encode(publicPoint.X, publicPoint.Y);
        Assert.IsTrue(P256EcdsaReference.Verify(publicKey, digest, rBytes, sBytes), "The reference must accept the signature (gate).");

        //e·G + r·Q + (n−s)·R = e·G + r·Q − s·R must vanish to O (null).
        (BigInteger X, BigInteger Y)? identity = OracleAdd(
            OracleAdd(OracleScalarMultiply(e, (GeneratorX, GeneratorY)), OracleScalarMultiply(r, publicPoint)),
            OracleScalarMultiply(ModOrder(-s), noncePoint));
        Assert.IsNull(identity, "e·G + r·Q − s·R must be the identity O for a valid signature.");

        //A tampered s breaks the identity: the sum is no longer O.
        (BigInteger X, BigInteger Y)? broken = OracleAdd(
            OracleAdd(OracleScalarMultiply(e, (GeneratorX, GeneratorY)), OracleScalarMultiply(r, publicPoint)),
            OracleScalarMultiply(ModOrder(-(s + BigInteger.One)), noncePoint));
        Assert.IsNotNull(broken, "A tampered s must break the identity.");
    }


    [TestMethod]
    public void EcdsaIdentityGadgetVerifiesForASatisfyingInstance()
    {
        //A reduced-width instance of the Alg.4 identity e·G + r·Q − s·R = O, proven
        //in-circuit over Fp256. With Q = 3·G, R = 2·G and scalars (e,r,s) = (5,3,7):
        //5·G + 3·(3G) − 7·(2G) = 5G + 9G − 14G = O. The full assembly runs — Q and R
        //on-curve, R negated to the third base, scalars bit-recomposed, the
        //three-scalar MSM, and the final assertion that the accumulator is O (Z = 0).
        //Full P-256 width is the identical gadget at 256 bits (cost documented in the
        //resume notes); the reformulation's full-scale fidelity is gated by
        //Alg4IdentityHoldsForARealP256SignatureAtFullScale.
        const int width = 3;
        (BigInteger qx, BigInteger qy) = ScalarMul(3, (GeneratorX, GeneratorY));
        (BigInteger rx, BigInteger ry) = ScalarMul(2, (GeneratorX, GeneratorY));

        Assert.IsNull(
            OracleAdd(OracleAdd(OracleScalarMultiply(5, (GeneratorX, GeneratorY)), OracleScalarMultiply(3, (qx, qy))),
                OracleScalarMultiply(ModOrder(-7), (rx, ry))),
            "The chosen instance must satisfy the identity (oracle gate).");

        var (builder, ec) = NewGadget();
        (int X, int Y, int Z) g = (Wire(builder, GeneratorX), Wire(builder, GeneratorY), Const(builder, BigInteger.One));
        (int X, int Y, int Z) q = (Wire(builder, qx), Wire(builder, qy), Const(builder, BigInteger.One));
        int rxWire = Wire(builder, rx), ryWire = Wire(builder, ry), rzWire = Const(builder, BigInteger.One);

        builder.AddOnCurveCheck(ec, q.X, q.Y);
        builder.AddOnCurveCheck(ec, rxWire, ryWire);

        //−R = (rx, −ry) is the third MSM base, so [s]·(−R) = −[s]·R.
        int negativeRy = builder.AddNegateY(ec, ryWire);

        int[] eBits = AddScalarBits(builder, 5, width);
        int[] rBits = AddScalarBits(builder, 3, width);
        int[] sBits = AddScalarBits(builder, 7, width);

        AssertRecomposes(builder, eBits, 5);
        AssertRecomposes(builder, rBits, 3);
        AssertRecomposes(builder, sBits, 7);

        (int X, int Y, int Z) sum = builder.AddThreeScalarMultiScalarMultiply(ec, g, q, (rxWire, negativeRy, rzWire), eBits, rBits, sBits);
        Assert.AreEqual(BigInteger.Zero, Val(builder, sum.Z), "The identity must make the accumulator O (Z = 0).");
        builder.AddAssertZero(sum.Z);

        using LigeroProof proof = ProveGadget(builder);
        Assert.IsTrue(VerifyGadget(builder, proof, TranscriptSeed), "An honest Alg.4 identity proof over Fp256 must verify.");

        proof.OpenedColumnMutable(0)[0] ^= 0x01;
        Assert.IsFalse(VerifyGadget(builder, proof, TranscriptSeed), "A tampered Alg.4 identity proof must be rejected.");
    }


    [TestMethod]
    public void EcdsaIdentityGadgetRejectsANonSatisfyingInstance()
    {
        //Same bases but e = 6 instead of 5: 6G + 9G − 14G = G ≠ O, so the
        //accumulator's Z ≠ 0 and the assert-O constraint is unsatisfiable — the
        //prover must refuse. Guards the binding that the MSM actually vanished.
        const int width = 3;
        (BigInteger qx, BigInteger qy) = ScalarMul(3, (GeneratorX, GeneratorY));
        (BigInteger rx, BigInteger ry) = ScalarMul(2, (GeneratorX, GeneratorY));

        var (builder, ec) = NewGadget();
        (int X, int Y, int Z) g = (Wire(builder, GeneratorX), Wire(builder, GeneratorY), Const(builder, BigInteger.One));
        (int X, int Y, int Z) q = (Wire(builder, qx), Wire(builder, qy), Const(builder, BigInteger.One));
        int rxWire = Wire(builder, rx), ryWire = Wire(builder, ry), rzWire = Const(builder, BigInteger.One);
        int negativeRy = builder.AddNegateY(ec, ryWire);

        int[] eBits = AddScalarBits(builder, 6, width);
        int[] rBits = AddScalarBits(builder, 3, width);
        int[] sBits = AddScalarBits(builder, 7, width);

        (int X, int Y, int Z) sum = builder.AddThreeScalarMultiScalarMultiply(ec, g, q, (rxWire, negativeRy, rzWire), eBits, rBits, sBits);
        Assert.AreNotEqual(BigInteger.Zero, Val(builder, sum.Z), "The non-satisfying instance must not vanish to O.");
        builder.AddAssertZero(sum.Z);

        Assert.ThrowsExactly<InvalidOperationException>(() => ProveGadget(builder).Dispose());
    }


    private static void AssertRecomposes(LigeroConstraintSystemBuilder builder, int[] bitsMostSignificantFirst, BigInteger expected)
    {
        int[] leastSignificantFirst = (int[])bitsMostSignificantFirst.Clone();
        Array.Reverse(leastSignificantFirst);
        int recomposed = builder.AddRecomposedScalar(leastSignificantFirst);
        Assert.AreEqual(expected, Val(builder, recomposed), "Recomposed scalar must equal its value.");
    }


    private static void LeftPad(byte[]? source, Span<byte> destination)
    {
        destination.Clear();
        ArgumentNullException.ThrowIfNull(source);
        source.CopyTo(destination[(destination.Length - source.Length)..]);
    }


    private static int[] AddScalarBits(LigeroConstraintSystemBuilder builder, BigInteger scalar, int width)
    {
        //Most-significant-first bit wires, each pinned to {0,1} by AddBit.
        int[] bitsMostSignificantFirst = new int[width];
        Span<byte> bit = stackalloc byte[ScalarSize];
        for(int i = 0; i < width; i++)
        {
            int bitIndex = width - 1 - i;
            WriteCanonical((scalar >> bitIndex) & BigInteger.One, bit);
            bitsMostSignificantFirst[i] = builder.AddBit(bit);
        }

        return bitsMostSignificantFirst;
    }


    private static (int X3, int Y3, int Z3) AddProjective(
        LigeroConstraintSystemBuilder builder, WeierstrassCurve ec, BigInteger x1, BigInteger y1, BigInteger z1, BigInteger x2, BigInteger y2, BigInteger z2)
    {
        int wx1 = Wire(builder, x1), wy1 = Wire(builder, y1), wz1 = Wire(builder, z1);
        int wx2 = Wire(builder, x2), wy2 = Wire(builder, y2), wz2 = Wire(builder, z2);

        return builder.AddCompleteProjectiveAddition(ec, wx1, wy1, wz1, wx2, wy2, wz2);
    }


    private static (BigInteger X, BigInteger Y)? Normalize(BigInteger x, BigInteger y, BigInteger z)
    {
        if(z.IsZero)
        {
            return null;
        }

        BigInteger inverse = ModInverse(z);

        return (Mod(x * inverse), Mod(y * inverse));
    }


    private readonly List<LigeroConstraintSystemBuilder> builders = [];


    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in builders)
        {
            builder.Dispose();
        }
    }


    private (LigeroConstraintSystemBuilder Builder, WeierstrassCurve Curve) NewGadget()
    {
        var builder = new LigeroConstraintSystemBuilder(
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);
        builders.Add(builder);

        return (builder, WeierstrassCurve.Create(builder, CurveABytes, CurveBBytes));
    }


    private static int Wire(LigeroConstraintSystemBuilder builder, BigInteger value)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        WriteCanonical(Mod(value), bytes);

        return builder.AddWire(bytes);
    }


    private static BigInteger Val(LigeroConstraintSystemBuilder builder, int wire) =>
        new(builder.Value(wire), isUnsigned: true, isBigEndian: true);


    private static int Const(LigeroConstraintSystemBuilder builder, BigInteger value)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        WriteCanonical(Mod(value), bytes);

        return builder.AddConstant(bytes);
    }


    private static LigeroProof ProveGadget(LigeroConstraintSystemBuilder builder) => LigeroProver.Prove(
        builder.BuildParameters(), builder.WitnessBytes(), builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), TranscriptSeed,
        new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
        P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static bool VerifyGadget(LigeroConstraintSystemBuilder builder, LigeroProof proof, ReadOnlySpan<byte> transcriptSeed) => LigeroVerifier.Verify(
        builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), transcriptSeed,
        P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static byte[] ToCanonical(BigInteger value)
    {
        byte[] bytes = new byte[ScalarSize];
        WriteCanonical(Mod(value), bytes);

        return bytes;
    }


    //--- Affine P-256 arithmetic over Fp256 (test oracle; mirrors the reference's formulas) ---

    private static BigInteger Mod(BigInteger v) => ((v % P) + P) % P;

    private static BigInteger ModInverse(BigInteger v) => BigInteger.ModPow(Mod(v), P - 2, P);


    private static (BigInteger X, BigInteger Y) AffineAdd((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) b)
    {
        //Test oracle: dispatch the equal-point case to doubling so callers need
        //not hand-pick examples that avoid it (the in-circuit gadget uses the
        //complete formula and needs no such care). Inverse points (sum = O) are
        //not produced by the chosen test vectors.
        if(a.X == b.X && a.Y == b.Y)
        {
            return AffineDouble(a);
        }

        BigInteger slope = Mod((b.Y - a.Y) * ModInverse(b.X - a.X));
        BigInteger x3 = Mod((slope * slope) - a.X - b.X);
        BigInteger y3 = Mod((slope * (a.X - x3)) - a.Y);

        return (x3, y3);
    }


    private static (BigInteger X, BigInteger Y) AffineDouble((BigInteger X, BigInteger Y) a)
    {
        BigInteger slope = Mod(((3 * a.X * a.X) + A) * ModInverse(2 * a.Y));
        BigInteger x3 = Mod((slope * slope) - (2 * a.X));
        BigInteger y3 = Mod((slope * (a.X - x3)) - a.Y);

        return (x3, y3);
    }


    //--- Identity-aware oracle (null = the point at infinity O) for full-scale
    //    Alg.4 verification, where intermediate and final sums may be O ---

    private static readonly BigInteger N = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);

    private static BigInteger ModOrder(BigInteger v) => ((v % N) + N) % N;

    private static (BigInteger X, BigInteger Y)? OracleAdd((BigInteger X, BigInteger Y)? a, (BigInteger X, BigInteger Y)? b)
    {
        if(a is null)
        {
            return b;
        }

        if(b is null)
        {
            return a;
        }

        //P + (−P) = O: same x, opposite y.
        if(a.Value.X == b.Value.X && Mod(a.Value.Y + b.Value.Y).IsZero)
        {
            return null;
        }

        return AffineAdd(a.Value, b.Value);
    }


    private static (BigInteger X, BigInteger Y)? OracleScalarMultiply(BigInteger scalar, (BigInteger X, BigInteger Y) point)
    {
        BigInteger k = ModOrder(scalar);
        (BigInteger X, BigInteger Y)? accumulator = null;
        (BigInteger X, BigInteger Y) addend = point;
        while(k > 0)
        {
            if(!(k & BigInteger.One).IsZero)
            {
                accumulator = OracleAdd(accumulator, addend);
            }

            addend = AffineDouble(addend);
            k >>= 1;
        }

        return accumulator;
    }


    private static (BigInteger X, BigInteger Y) ScalarMul(int scalar, (BigInteger X, BigInteger Y) point)
    {
        (BigInteger X, BigInteger Y)? accumulator = null;
        (BigInteger X, BigInteger Y) addend = point;
        for(int k = scalar; k > 0; k >>= 1)
        {
            if((k & 1) == 1)
            {
                accumulator = accumulator is null ? addend : AffineAdd(accumulator.Value, addend);
            }

            addend = AffineDouble(addend);
        }

        return accumulator!.Value;
    }


    private static byte[] Encode(BigInteger x, BigInteger y)
    {
        byte[] compressed = new byte[CompressedSize];
        compressed[0] = (byte)(0x02 | (byte)(y & BigInteger.One));
        WriteCanonical(x, compressed.AsSpan(1));

        return compressed;
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    //A reproducible Fp256 randomness source: BLAKE3-XOF of seed‖counter reduced
    //modulo the base-field prime.
    private sealed class DeterministicFp256Random
    {
        private readonly byte[] seed;
        private int counter;

        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);
            WriteCanonical(new BigInteger(wide, isUnsigned: true, isBigEndian: true) % P, destination);

            return inboundTag;
        }
    }
}
