using Lumoin.Veridical.Core.Diagnostics;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Structural-invariant tests for the BLS12-381 canonical constants
/// declared in <see cref="Bls12Curve381BigIntegerG1Reference"/> and
/// referenced by the leaf algebraic types.
/// </summary>
/// <remarks>
/// <para>
/// Each canonical value the library declares (base field prime, scalar
/// field order, curve <c>b</c>, generator <c>(x, y)</c>) is verified
/// against a mathematical invariant that cannot agree with a
/// transcription error by accident. Primality is checked via Miller-Rabin
/// (Fermat-style witnesses that succeed only for genuinely prime values);
/// the generator coordinates are checked against the curve equation
/// <c>y^2 ≡ x^3 + 4 (mod p)</c>. The constants declared at the top of
/// this class are then asserted equal to the runtime constants used by
/// the reference backend, so a future divergence between the declared
/// canonical value and the value the backend computes against surfaces
/// immediately.
/// </para>
/// <para>
/// The tests in this class fail fast and with a clear cause when any
/// constant drifts away from the canonical value — the most recent batch
/// B regression (a four-hex-digit typo in <c>BaseFieldPrime</c>) would
/// have failed <see cref="BaseFieldPrimeIsPrime"/> in milliseconds with a
/// message naming the suspect constant, rather than the actual failure
/// path which surfaced as a generic "input bytes do not encode a valid
/// G1 point" several layers below in the decode logic.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381CanonicalConstantsTests
{
    //Canonical BLS12-381 base field prime, per IETF draft-irtf-cfrg-pairing-friendly-curves §4.2.1
    //and EIP-2537. A typo anywhere in this literal is overwhelmingly likely to make the value
    //composite, which BaseFieldPrimeIsPrime catches via Miller-Rabin.
    private static readonly BigInteger CanonicalBaseFieldPrime = BigInteger.Parse(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    //Canonical BLS12-381 scalar field order. Same reasoning applies: a typo makes the value composite.
    private static readonly BigInteger CanonicalScalarFieldOrder = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    //Canonical BLS12-381 G1 generator x-coordinate.
    private static readonly BigInteger CanonicalGeneratorX = BigInteger.Parse(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    //Canonical BLS12-381 G1 generator y-coordinate.
    private static readonly BigInteger CanonicalGeneratorY = BigInteger.Parse(
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    [TestMethod]
    public void BaseFieldPrimeIsPrime()
    {
        //If this fails, the BaseFieldPrime literal carries a typo. Inspect this
        //file's CanonicalBaseFieldPrime against an authoritative source (RFC 9380
        //§4.2.1 or EIP-2537) — the first witness Miller-Rabin found is almost
        //certainly distinguishing the wrong value from the real prime.
        Assert.IsTrue(
            PrimalityDiagnostics.IsLikelyPrime(CanonicalBaseFieldPrime),
            "CanonicalBaseFieldPrime must be prime. Likely cause of failure: a typo in the hex literal of p.");
    }


    [TestMethod]
    public void ScalarFieldOrderIsPrime()
    {
        //Same diagnostic as BaseFieldPrimeIsPrime, but for the scalar field
        //order r used by Scalar arithmetic.
        Assert.IsTrue(
            PrimalityDiagnostics.IsLikelyPrime(CanonicalScalarFieldOrder),
            "CanonicalScalarFieldOrder must be prime. Likely cause of failure: a typo in the hex literal of r.");
    }


    [TestMethod]
    public void GeneratorSatisfiesCurveEquation()
    {
        //Verifies y^2 ≡ x^3 + 4 (mod p) for the canonical generator. If this
        //fails when BaseFieldPrimeIsPrime passes, the typo is in x_gen or y_gen.
        //If it fails together with BaseFieldPrimeIsPrime, the typo is in p.
        Assert.IsTrue(
            WeierstrassDiagnostics.SatisfiesShortWeierstrass(
                CanonicalGeneratorX,
                CanonicalGeneratorY,
                a: BigInteger.Zero,
                b: new BigInteger(4),
                p: CanonicalBaseFieldPrime),
            "Generator coordinates must satisfy y^2 ≡ x^3 + 4 (mod p). Likely cause of failure: a typo in x_gen, y_gen, or p.");
    }


    [TestMethod]
    public void ReferenceBaseFieldPrimeMatchesCanonical()
    {
        //If this fails, the reference backend and this test class disagree on
        //what the BLS12-381 base field prime is. The canonical value above is
        //the source of truth — fix the reference.
        Assert.AreEqual(
            CanonicalBaseFieldPrime,
            Bls12Curve381BigIntegerG1Reference.BaseFieldPrime,
            "Reference's BaseFieldPrime must equal the canonical BLS12-381 base field prime declared by this test class.");
    }


    [TestMethod]
    public void ReferenceScalarFieldOrderMatchesCanonical()
    {
        Assert.AreEqual(
            CanonicalScalarFieldOrder,
            Bls12Curve381BigIntegerG1Reference.ScalarFieldOrder,
            "Reference's ScalarFieldOrder must equal the canonical BLS12-381 scalar field order declared by this test class.");
    }


    [TestMethod]
    public void ReferenceCurveBMatchesCanonical()
    {
        Assert.AreEqual(
            new BigInteger(4),
            Bls12Curve381BigIntegerG1Reference.CurveB,
            "Reference's CurveB must equal 4 for the BLS12-381 G1 curve y^2 = x^3 + 4.");
    }
}