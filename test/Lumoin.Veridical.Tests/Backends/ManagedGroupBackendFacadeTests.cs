using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Bbs;
using System;

namespace Lumoin.Veridical.Tests.Backends;

/// <summary>
/// Validates the public managed curve-group and pairing composition roots added so
/// external NuGet consumers can wire the full BLS12-381 BBS+ sign/verify path from
/// shipped types alone (the underlying reference backends are internal). The
/// headline tests drive a complete keygen + Sign + Verify exclusively through the
/// public <c>Create()</c> facades, for both BBS+ ciphersuites; the shape tests pin
/// each bundle's curve identity and the nullable-member contract.
/// </summary>
[TestClass]
internal sealed class ManagedGroupBackendFacadeTests
{
    private static readonly byte[] KeyMaterial = MakeBytes(64, 0x10);
    private static readonly byte[] KeyInfo = "facade-key-info"u8.ToArray();
    private static readonly byte[] Header = "facade-header"u8.ToArray();


    [TestMethod]
    public void PublicFacadesDriveBbsSignVerifyRoundtripSha256()
    {
        RunBbsRoundtrip(
            BbsCiphersuite.Bls12Curve381Sha256,
            Rfc9380ExpandMessage.ExpandMessageXmdSha256,
            Bls12Curve381ManagedScalarBackend.GetHashToScalarSha256(),
            Bls12Curve381ManagedG1Backend.GetHashToCurveSha256());
    }


    [TestMethod]
    public void PublicFacadesDriveBbsSignVerifyRoundtripShake256()
    {
        RunBbsRoundtrip(
            BbsCiphersuite.Bls12Curve381Shake256,
            Rfc9380ExpandMessage.ExpandMessageXofShake256,
            Bls12Curve381ManagedScalarBackend.GetHashToScalarShake256(),
            Bls12Curve381ManagedG1Backend.GetHashToCurveShake256());
    }


    private static void RunBbsRoundtrip(
        BbsCiphersuite suite,
        ExpandMessageDelegate expandMessage,
        ScalarHashToScalarDelegate hashToScalar,
        G1HashToCurveDelegate g1HashToCurve)
    {
        using ScalarArithmeticBackend scalar = Bls12Curve381ManagedScalarBackend.Create();
        using G1ArithmeticBackend g1 = Bls12Curve381ManagedG1Backend.Create();
        using G2ArithmeticBackend g2 = Bls12Curve381ManagedG2Backend.Create();
        using PairingBackend pairing = Bls12Curve381ManagedPairingBackend.Create();

        BbsMessage[] messages =
        [
            new BbsMessage("facade-message-one"u8.ToArray()),
            new BbsMessage("facade-message-two"u8.ToArray()),
        ];

        using BbsKeyPair pair = suite.Generate(
            KeyMaterial,
            KeyInfo,
            hashToScalar,
            g2.ScalarMultiply,
            TestSetup.Pool);

        using BbsSignature signature = pair.SecretKey.Sign(
            pair.PublicKey,
            new BbsHeader(Header),
            messages,
            expandMessage,
            hashToScalar,
            scalar.Add,
            scalar.Invert,
            g1.Add,
            g1.ScalarMultiply,
            g1.MultiScalarMultiply,
            g1HashToCurve,
            TestSetup.Pool);

        bool verified = pair.PublicKey.Verify(
            signature,
            new BbsHeader(Header),
            messages,
            expandMessage,
            hashToScalar,
            g1.Add,
            g1.MultiScalarMultiply,
            g1HashToCurve,
            g1.IsOnCurve!,
            g1.IsInPrimeOrderSubgroup!,
            g2.Add,
            g2.ScalarMultiply,
            g2.IsOnCurve!,
            g2.IsInPrimeOrderSubgroup!,
            pairing.Pairing,
            TestSetup.Pool);

        Assert.IsTrue(verified, $"BBS+ sign/verify through the public managed facades must verify for {suite.Identifier}.");
    }


    [TestMethod]
    public void G1FacadesExposeExpectedCurveAndPredicateShape()
    {
        using G1ArithmeticBackend bls = Bls12Curve381ManagedG1Backend.Create();
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, bls.Curve);
        Assert.IsNotNull(bls.IsOnCurve, "BLS12-381 G1 supplies an on-curve predicate.");
        Assert.IsNotNull(bls.IsInPrimeOrderSubgroup, "BLS12-381 G1 supplies a subgroup predicate.");

        using G1ArithmeticBackend bn = Bn254ManagedG1Backend.Create();
        Assert.AreEqual(CurveParameterSet.Bn254, bn.Curve);
        Assert.IsNotNull(bn.IsOnCurve, "BN254 G1 supplies an on-curve predicate.");
        Assert.IsNotNull(bn.IsInPrimeOrderSubgroup, "BN254 G1 supplies a subgroup predicate.");

        using G1ArithmeticBackend p256 = P256ManagedG1Backend.Create();
        Assert.AreEqual(CurveParameterSet.P256, p256.Curve);
        Assert.IsNull(p256.IsOnCurve, "The P-256 reference omits the on-curve predicate, so the bundle member is null.");
        Assert.IsNull(p256.IsInPrimeOrderSubgroup, "The P-256 reference omits the subgroup predicate, so the bundle member is null.");
    }


    [TestMethod]
    public void G2AndPairingFacadesExposeExpectedCurveShape()
    {
        using G2ArithmeticBackend blsG2 = Bls12Curve381ManagedG2Backend.Create();
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, blsG2.Curve);
        using G2ArithmeticBackend bnG2 = Bn254ManagedG2Backend.Create();
        Assert.AreEqual(CurveParameterSet.Bn254, bnG2.Curve);

        using PairingBackend blsPairing = Bls12Curve381ManagedPairingBackend.Create();
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, blsPairing.Curve);
        Assert.IsNotNull(blsPairing.Frobenius, "The BLS12-381 pairing backend supplies the Fp12 Frobenius.");
        Assert.IsNotNull(blsPairing.CyclotomicSquare, "The BLS12-381 pairing backend supplies the Fp12 cyclotomic square.");

        using PairingBackend bnPairing = Bn254ManagedPairingBackend.Create();
        Assert.AreEqual(CurveParameterSet.Bn254, bnPairing.Curve);
        Assert.IsNotNull(bnPairing.Frobenius, "The BN254 pairing backend supplies the Fp12 Frobenius.");
        Assert.IsNotNull(bnPairing.CyclotomicSquare, "The BN254 pairing backend supplies the Fp12 cyclotomic square.");
    }


    [TestMethod]
    public void ScalarFacadesExposeExpectedCurveAndHashShape()
    {
        using ScalarArithmeticBackend bls = Bls12Curve381ManagedScalarBackend.Create();
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, bls.Curve);
        Assert.IsNotNull(bls.HashToScalar, "BLS12-381 bakes in the SHA-256 hash-to-scalar.");

        using ScalarArithmeticBackend bn = Bn254ManagedScalarBackend.Create();
        Assert.AreEqual(CurveParameterSet.Bn254, bn.Curve);
        Assert.IsNull(bn.HashToScalar, "BN254 takes expand-message as a parameter, so the bundle hash-to-scalar is null.");

        using ScalarArithmeticBackend p256 = P256ManagedScalarBackend.Create();
        Assert.AreEqual(CurveParameterSet.P256, p256.Curve);
        Assert.IsNull(p256.HashToScalar, "P-256 takes expand-message as a parameter, so the bundle hash-to-scalar is null.");
        Assert.IsFalse(p256.IsHardwareAccelerated, "P-256 has no SIMD scalar backend, so the bundle is never hardware-accelerated.");
    }


    private static byte[] MakeBytes(int length, byte start)
    {
        byte[] result = new byte[length];
        for(int i = 0; i < length; i++)
        {
            result[i] = (byte)(start + i);
        }

        return result;
    }
}
