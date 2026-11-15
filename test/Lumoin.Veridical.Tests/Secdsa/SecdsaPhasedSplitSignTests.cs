using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the phased split sign of <see cref="SecdsaAlgorithm"/>: <see cref="SecdsaAlgorithm.PrepareSplitSign"/>
/// and <see cref="SecdsaAlgorithm.CompleteSplitSign"/> with a simulated external key holder between them. The
/// phased result must be byte-identical to the all-software path for the same inputs (RFC 6979 nonces make both
/// deterministic), the completion must reject every defective key-holder answer and release nothing when it does,
/// and the two-party key-share flow of Algorithm 11 must be expressible with the same two phases applied once per
/// party.
/// </summary>
[TestClass]
internal sealed class SecdsaPhasedSplitSignTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;

    private const string PinKeyHex = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
    private const string HardwareKeyHex = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    private const string WalletShareHex = "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80912";
    private const string WscaShareHex = "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a23";
    private const string BaseKeyHex = "4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b34";
    private const string MessageHashHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string OtherMessageHashHex = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    private const string ZeroScalarHex = "0000000000000000000000000000000000000000000000000000000000000000";
    private const string ShortHashHex = "01";
    private const string OrderHex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    private static byte[] PinKey { get; } = Convert.FromHexString(PinKeyHex);
    private static byte[] HardwareKey { get; } = Convert.FromHexString(HardwareKeyHex);
    private static byte[] WalletShare { get; } = Convert.FromHexString(WalletShareHex);
    private static byte[] WscaShare { get; } = Convert.FromHexString(WscaShareHex);
    private static byte[] BaseKey { get; } = Convert.FromHexString(BaseKeyHex);
    private static byte[] MessageHash { get; } = Convert.FromHexString(MessageHashHex);
    private static byte[] OtherMessageHash { get; } = Convert.FromHexString(OtherMessageHashHex);
    private static byte[] Order { get; } = Convert.FromHexString(OrderHex);
    private static byte[] ZeroScalar { get; } = Convert.FromHexString(ZeroScalarHex);
    private static byte[] ShortHash { get; } = Convert.FromHexString(ShortHashHex);

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static ScalarAddDelegate ScalarAdd { get; } = P256BigIntegerScalarReference.GetAdd();
    private static ScalarInvertDelegate ScalarInvert { get; } = P256BigIntegerScalarReference.GetInvert();
    private static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static G1AddDelegate G1Add { get; } = P256BigIntegerG1Reference.GetAdd();

    private static SecdsaNonceSource Rfc6979NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);


    [TestMethod]
    public void PhasedSignWithSimulatedKeyHolderIsByteIdenticalToAllSoftwareSign()
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(PinKey, HardwareKey, ScalarMultiply, G1ScalarMultiply, publicKey);

        Span<byte> blinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(PinKey, MessageHash, ScalarMultiply, ScalarInvert, ScalarReduce, blinded);

        //The key holder is outside the library: it sees only e' and answers (r, s0).
        Span<byte> keyHolderR = stackalloc byte[ScalarSize];
        Span<byte> keyHolderS0 = stackalloc byte[ScalarSize];
        KeyHolderRawSign(HardwareKey, blinded, keyHolderR, keyHolderS0);

        Span<byte> phasedS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.CompleteSplitSign(
            PinKey, MessageHash, publicKey, keyHolderR, keyHolderS0,
            ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, phasedS);

        Span<byte> softwareR = stackalloc byte[ScalarSize];
        Span<byte> softwareS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            PinKey, HardwareKey, MessageHash, Rfc6979NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add,
            softwareR, softwareS);

        Assert.IsTrue(keyHolderR.SequenceEqual(softwareR), "The phased r must byte-match the all-software r.");
        Assert.IsTrue(phasedS.SequenceEqual(softwareS), "The phased s must byte-match the all-software s.");
    }


    [TestMethod]
    public void RawSignSeamRunsThroughTheSamePhasesAndMatchesAllSoftwareSign()
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(PinKey, HardwareKey, ScalarMultiply, G1ScalarMultiply, publicKey);

        SecdsaRawEcdsaSign hardwareLike = (blindedHash, r, s0) => KeyHolderRawSign(HardwareKey, blindedHash, r, s0);

        Span<byte> seamR = stackalloc byte[ScalarSize];
        Span<byte> seamS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            PinKey, MessageHash, publicKey, hardwareLike,
            ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add,
            seamR, seamS);

        Span<byte> softwareR = stackalloc byte[ScalarSize];
        Span<byte> softwareS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            PinKey, HardwareKey, MessageHash, Rfc6979NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add,
            softwareR, softwareS);

        Assert.IsTrue(seamR.SequenceEqual(softwareR), "The seam r must byte-match the all-software r.");
        Assert.IsTrue(seamS.SequenceEqual(softwareS), "The seam s must byte-match the all-software s.");
    }


    [TestMethod]
    public void PreparedRepresentativeIsTheInverseBlindOfTheHash()
    {
        //e' = P^-1 * e, so P * e' = e (mod n): the independent check of the prepare output.
        Span<byte> blinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(PinKey, MessageHash, ScalarMultiply, ScalarInvert, ScalarReduce, blinded);

        Span<byte> unblinded = stackalloc byte[ScalarSize];
        ScalarMultiply(PinKey, blinded, unblinded, CurveParameterSet.P256);
        Span<byte> reducedHash = stackalloc byte[ScalarSize];
        ScalarReduce(MessageHash, reducedHash, CurveParameterSet.P256);

        Assert.IsTrue(unblinded.SequenceEqual(reducedHash), "P * e' must equal e mod n.");
    }


    [TestMethod]
    public void CompleteRejectsATamperedRawSignatureAndReleasesNothing()
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(PinKey, HardwareKey, ScalarMultiply, G1ScalarMultiply, publicKey);
        Span<byte> blinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(PinKey, MessageHash, ScalarMultiply, ScalarInvert, ScalarReduce, blinded);
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s0 = stackalloc byte[ScalarSize];
        KeyHolderRawSign(HardwareKey, blinded, r, s0);

        Span<byte> flippedS0 = stackalloc byte[ScalarSize];
        s0.CopyTo(flippedS0);
        flippedS0[^1] ^= 0x01;
        AssertCompletionRejected(PinKey, MessageHash, publicKey, r, flippedS0, "a flipped bit in s0");

        Span<byte> flippedR = stackalloc byte[ScalarSize];
        r.CopyTo(flippedR);
        flippedR[^1] ^= 0x01;
        AssertCompletionRejected(PinKey, MessageHash, publicKey, flippedR, s0, "a flipped bit in r");
    }


    [TestMethod]
    public void CompleteRejectsZeroAndOutOfRangeComponents()
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(PinKey, HardwareKey, ScalarMultiply, G1ScalarMultiply, publicKey);
        Span<byte> blinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(PinKey, MessageHash, ScalarMultiply, ScalarInvert, ScalarReduce, blinded);
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s0 = stackalloc byte[ScalarSize];
        KeyHolderRawSign(HardwareKey, blinded, r, s0);
        Span<byte> zero = stackalloc byte[ScalarSize];

        AssertCompletionRejected(PinKey, MessageHash, publicKey, zero, s0, "r = 0");
        AssertCompletionRejected(PinKey, MessageHash, publicKey, r, zero, "s0 = 0");
        AssertCompletionRejected(PinKey, MessageHash, publicKey, Order, s0, "r = n");
        AssertCompletionRejected(PinKey, MessageHash, publicKey, r, Order, "s0 = n");
    }


    [TestMethod]
    public void CompleteRejectsAWrongPublicKeyAndAWrongMessage()
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(PinKey, HardwareKey, ScalarMultiply, G1ScalarMultiply, publicKey);
        Span<byte> otherPublicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(WalletShare, HardwareKey, ScalarMultiply, G1ScalarMultiply, otherPublicKey);
        Span<byte> blinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(PinKey, MessageHash, ScalarMultiply, ScalarInvert, ScalarReduce, blinded);
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s0 = stackalloc byte[ScalarSize];
        KeyHolderRawSign(HardwareKey, blinded, r, s0);

        AssertCompletionRejected(PinKey, MessageHash, otherPublicKey, r, s0, "a public key of a different composite key");
        AssertCompletionRejected(PinKey, OtherMessageHash, publicKey, r, s0, "an answer for a different message");
        AssertCompletionRejected(WalletShare, MessageHash, publicKey, r, s0, "a different PIN key");

        //A key holder that signed with a different hardware key is rejected even though its answer is well formed.
        Span<byte> impostorR = stackalloc byte[ScalarSize];
        Span<byte> impostorS0 = stackalloc byte[ScalarSize];
        KeyHolderRawSign(WscaShare, blinded, impostorR, impostorS0);
        AssertCompletionRejected(PinKey, MessageHash, publicKey, impostorR, impostorS0, "an answer signed under a different hardware key");
    }


    [TestMethod]
    public void RawSignSeamClearsItsOutputsWhenTheKeyHolderIsFaulty()
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(PinKey, HardwareKey, ScalarMultiply, G1ScalarMultiply, publicKey);

        SecdsaRawEcdsaSign faulty = (blindedHash, r, s0) =>
        {
            KeyHolderRawSign(HardwareKey, blindedHash, r, s0);
            s0[^1] ^= 0x01;
        };

        Span<byte> outR = stackalloc byte[ScalarSize];
        Span<byte> outS = stackalloc byte[ScalarSize];
        bool rejected = false;
        try
        {
            SecdsaAlgorithm.SplitSign(
                PinKey, MessageHash, publicKey, faulty,
                ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add,
                outR, outS);
        }
        catch(InvalidOperationException)
        {
            rejected = true;
        }

        Assert.IsTrue(rejected, "A faulty key holder must make the seam throw.");
        Assert.AreEqual(-1, outR.IndexOfAnyExcept((byte)0), "r must be cleared after a rejected answer.");
        Assert.AreEqual(-1, outS.IndexOfAnyExcept((byte)0), "s must be cleared after a rejected answer.");
    }


    [TestMethod]
    public void PrepareAndCompleteRejectInvalidPinKeysAndLengths()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => PrepareInto(ZeroScalar, MessageHash),
            "P = 0 must be rejected by prepare.");
        Assert.ThrowsExactly<ArgumentException>(
            () => PrepareInto(Order, MessageHash),
            "P = n must be rejected by prepare.");
        Assert.ThrowsExactly<ArgumentException>(
            () => PrepareInto(PinKey, ShortHash),
            "A short message hash must be rejected by prepare.");
    }


    [TestMethod]
    public void TwoPartyKeySharesAreExpressibleByApplyingThePhasesOncePerParty()
    {
        //Algorithm 11: the wallet blinds with zU (step 2), the WSCA blinds with zW (step 4), the HSM raw-signs
        //under bU (step 6), the WSCA masks with zW (step 8) and the wallet masks with zU (step 10). The
        //product zU*zW is never formed. The result is byte-identical to the all-software sign under P = zU*zW.
        Span<byte> finalPublicKey = stackalloc byte[CompressedSize];
        Span<byte> intermediatePublicKey = stackalloc byte[CompressedSize];
        Span<byte> composedPin = stackalloc byte[ScalarSize];
        ScalarMultiply(WalletShare, WscaShare, composedPin, CurveParameterSet.P256);
        SecdsaAlgorithm.DeriveSplitPublicKey(composedPin, BaseKey, ScalarMultiply, G1ScalarMultiply, finalPublicKey);
        SecdsaAlgorithm.DeriveSplitPublicKey(WscaShare, BaseKey, ScalarMultiply, G1ScalarMultiply, intermediatePublicKey);

        Span<byte> walletBlinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(WalletShare, MessageHash, ScalarMultiply, ScalarInvert, ScalarReduce, walletBlinded);
        Span<byte> wscaBlinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(WscaShare, walletBlinded, ScalarMultiply, ScalarInvert, ScalarReduce, wscaBlinded);

        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> hsmS = stackalloc byte[ScalarSize];
        KeyHolderRawSign(BaseKey, wscaBlinded, r, hsmS);

        Span<byte> wscaS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.CompleteSplitSign(
            WscaShare, walletBlinded, intermediatePublicKey, r, hsmS,
            ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, wscaS);
        Span<byte> walletS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.CompleteSplitSign(
            WalletShare, MessageHash, finalPublicKey, r, wscaS,
            ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, walletS);

        Span<byte> softwareR = stackalloc byte[ScalarSize];
        Span<byte> softwareS = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.SplitSign(
            composedPin, BaseKey, MessageHash, Rfc6979NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add,
            softwareR, softwareS);

        Assert.IsTrue(r.SequenceEqual(softwareR), "The two-party r must byte-match the all-software r under P = zU*zW.");
        Assert.IsTrue(walletS.SequenceEqual(softwareS), "The two-party s must byte-match the all-software s under P = zU*zW.");
        Assert.IsTrue(
            SecdsaAlgorithm.Verify(finalPublicKey, MessageHash, r, walletS, ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add),
            "The two-party signature must verify under Y = (zU*zW*bU)*G.");
    }


    [TestMethod]
    public void WscaCompletionRejectsAFaultyHsmBeforeTheWalletSeesIt()
    {
        Span<byte> intermediatePublicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(WscaShare, BaseKey, ScalarMultiply, G1ScalarMultiply, intermediatePublicKey);

        Span<byte> walletBlinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(WalletShare, MessageHash, ScalarMultiply, ScalarInvert, ScalarReduce, walletBlinded);
        Span<byte> wscaBlinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(WscaShare, walletBlinded, ScalarMultiply, ScalarInvert, ScalarReduce, wscaBlinded);
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> hsmS = stackalloc byte[ScalarSize];
        KeyHolderRawSign(BaseKey, wscaBlinded, r, hsmS);
        hsmS[0] ^= 0x01;

        AssertCompletionRejected(WscaShare, walletBlinded, intermediatePublicKey, r, hsmS, "a faulty HSM answer at the WSCA");
    }


    //The simulated external key holder: raw ECDSA with RFC 6979 over (key, e'), by the independent reference signer.
    private static void KeyHolderRawSign(ReadOnlySpan<byte> hardwareKey, ReadOnlySpan<byte> blindedHash, Span<byte> r, Span<byte> s0)
    {
        Span<byte> nonce = stackalloc byte[ScalarSize];
        try
        {
            Rfc6979DeterministicNonce.GenerateNonce(CurveParameterSet.P256, hardwareKey, blindedHash, Sha256Hmac.Compute, nonce);
            P256EcdsaReference.Sign(hardwareKey, blindedHash, nonce, r, s0);
        }
        finally
        {
            nonce.Clear();
        }
    }


    private static void PrepareInto(ReadOnlySpan<byte> pinKey, ReadOnlySpan<byte> messageHash)
    {
        Span<byte> blinded = stackalloc byte[ScalarSize];
        SecdsaAlgorithm.PrepareSplitSign(pinKey, messageHash, ScalarMultiply, ScalarInvert, ScalarReduce, blinded);
    }


    private static void AssertCompletionRejected(
        ReadOnlySpan<byte> pinKey,
        ReadOnlySpan<byte> messageHash,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s0,
        string scenario)
    {
        Span<byte> s = stackalloc byte[ScalarSize];
        s.Fill(0xAA);
        bool rejected = false;
        try
        {
            SecdsaAlgorithm.CompleteSplitSign(
                pinKey, messageHash, publicKey, r, s0,
                ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, s);
        }
        catch(InvalidOperationException)
        {
            rejected = true;
        }

        Assert.IsTrue(rejected, $"Completion must reject {scenario}.");
        Assert.AreEqual(-1, s.IndexOfAnyExcept((byte)0), $"Completion must release nothing for {scenario}.");
    }
}
