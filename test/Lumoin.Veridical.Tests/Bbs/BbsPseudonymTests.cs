using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Structural gates for <see cref="BbsPseudonym.FromCanonical"/>: the
/// fixed 48-byte compressed-G1-point length, and the two forbidden
/// values per <c>draft-irtf-cfrg-bbs-per-verifier-linkability-03</c>
/// Section 3.3 — the G1 identity and the G1 base point BP1.
/// </summary>
[TestClass]
internal sealed class BbsPseudonymTests
{
    private static readonly BbsCiphersuite Suite = BbsCiphersuite.Bls12Curve381Sha256Pseudonym;

    //Neither the identity nor BP1: an arbitrary 48-byte pattern. FromCanonical
    //performs no on-curve check (deferred to the operation surfaces), so this
    //is a valid probe for "everything except the two forbidden values".
    private static readonly byte[] NeitherIdentityNorBp1 = BuildArbitraryPattern();


    [TestMethod]
    public void FromCanonicalRejectsWrongLength()
    {
        byte[] tooShort = new byte[BbsPseudonym.SizeBytes - 1];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsPseudonym.FromCanonical(tooShort, Suite, TestSetup.Pool));
        Assert.Contains("exactly", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsIdentity()
    {
        //A ReadOnlySpan<byte> local cannot be captured by the lambda ThrowsExactly
        //takes, so the identity encoding is looked up fresh inside the lambda body.
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsPseudonym.FromCanonical(WellKnownCurves.GetG1IdentityCompressed(CurveParameterSet.Bls12Curve381), Suite, TestSetup.Pool));
        Assert.Contains("identity", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsBp1()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsPseudonym.FromCanonical(WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381), Suite, TestSetup.Pool));
        Assert.Contains("BP1", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalAcceptsAnyOtherFortyEightByteValue()
    {
        using BbsPseudonym pseudonym = BbsPseudonym.FromCanonical(NeitherIdentityNorBp1, Suite, TestSetup.Pool);

        Assert.IsTrue(((ReadOnlySpan<byte>)NeitherIdentityNorBp1).SequenceEqual(pseudonym.GetPseudonymBytes()));
    }


    [TestMethod]
    public void CiphersuiteTagRoundTripsThroughFromCanonical()
    {
        using BbsPseudonym shaPseudonym = BbsPseudonym.FromCanonical(NeitherIdentityNorBp1, BbsCiphersuite.Bls12Curve381Sha256Pseudonym, TestSetup.Pool);
        using BbsPseudonym shakePseudonym = BbsPseudonym.FromCanonical(NeitherIdentityNorBp1, BbsCiphersuite.Bls12Curve381Shake256Pseudonym, TestSetup.Pool);

        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256Pseudonym, shaPseudonym.Ciphersuite);
        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Shake256Pseudonym, shakePseudonym.Ciphersuite);
    }


    [TestMethod]
    public void GetAlgebraicTagRejectsTheCoreCiphersuite()
    {
        //Pseudonyms are Interface- and ciphersuite-specific by design
        //(linking across Interfaces is explicitly out of scope for the
        //draft), so the core ciphersuite must be rejected rather than
        //accepted.
        Assert.ThrowsExactly<ArgumentException>(() => _ = BbsPseudonym.GetAlgebraicTag(BbsCiphersuite.Bls12Curve381Sha256));
    }


    private static byte[] BuildArbitraryPattern()
    {
        byte[] pattern = new byte[BbsPseudonym.SizeBytes];
        for(int i = 0; i < pattern.Length; i++)
        {
            pattern[i] = (byte)(0x40 + i);
        }

        return pattern;
    }
}
