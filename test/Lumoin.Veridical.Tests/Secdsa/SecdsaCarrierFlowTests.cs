using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// End-to-end SECDSA gate over P-256 driven through the broad, Tag-disciplined leaf carriers a real consumer uses
/// (<see cref="Scalar"/>, <see cref="G1Point"/>, <see cref="SecdsaSignature"/>, <see cref="DlEqualityProof"/>),
/// rather than the raw <c>byte[]</c> the other SECDSA gates use. The carrier construction factories
/// (<see cref="Scalar.FromRandom"/>, <see cref="Scalar.FromBytesReduced"/>, <see cref="G1Point.Generator"/>,
/// <see cref="G1Point.FromCanonical(System.ReadOnlySpan{byte}, CurveParameterSet, Lumoin.Base.BaseMemoryPool, Tag?)"/>)
/// resolve a per-curve algebraic-identity tag from <see cref="WellKnownAlgebraicTags"/>; this gate exercises that
/// path for P-256, which the raw-span gates never did — the omission that let a missing P-256 tag entry ship.
/// </summary>
/// <remarks>
/// The flow mirrors the wallet-provider WSCA application path: activation blinds the SECDSA public key, signing
/// produces a split-ECDSA signature, and the wallet-provider control evidence binds <c>R' = aU·R</c> to the
/// transaction record. The mod-<c>n</c> scalar and group arithmetic is wired from the BigInteger references, the
/// same reuse-by-injection the other SECDSA gates use.
/// </remarks>
[TestClass]
internal sealed class SecdsaCarrierFlowTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;
    private static CurveParameterSet Curve => CurveParameterSet.P256;

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static ScalarAddDelegate ScalarAdd { get; } = P256BigIntegerScalarReference.GetAdd();
    private static ScalarInvertDelegate ScalarInvert { get; } = P256BigIntegerScalarReference.GetInvert();
    private static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();
    private static ScalarRandomDelegate ScalarRandom { get; } = P256BigIntegerScalarReference.GetRandom();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static G1AddDelegate G1Add { get; } = P256BigIntegerG1Reference.GetAdd();
    private static G1NegateDelegate G1Negate { get; } = P256BigIntegerG1Reference.GetNegate();

    private static SecdsaNonceSource NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);
    private static FiatShamirHashDelegate Hash { get; } = Sha256FiatShamir;


    [TestMethod]
    public void FullSecdsaFlowOverP256HoldsThroughTaggedBroadCarriers()
    {
        using var pool = new BaseMemoryPool();

        //-- ACTIVATION: mint the keys as tagged P-256 scalars from the entropy boundary factory --
        //
        //FromRandom is the factory that first surfaced the missing P-256 tag entry. P is the PIN-key,
        //u the NCH hardware key, t the wallet's one-time blinding scalar, aU the HSM-bound blinding key.
        using Scalar pinKey = Scalar.FromRandom(ScalarRandom, Curve, pool);
        using Scalar hardwareKey = Scalar.FromRandom(ScalarRandom, Curve, pool);
        using Scalar blinding = Scalar.FromRandom(ScalarRandom, Curve, pool);
        using Scalar walletProviderKey = Scalar.FromRandom(ScalarRandom, Curve, pool);

        Assert.AreEqual(Curve, pinKey.Curve, "A scalar minted for P-256 must carry the P-256 curve tag.");

        using G1Point generator = G1Point.Generator(Curve, pool);

        //Y = (P*u)*G, the raw SECDSA public key, as a tagged compressed point.
        using G1Point publicKey = DeriveSplitPublicKey(pinKey, hardwareKey, pool);
        Assert.AreEqual(Curve, publicKey.Curve, "The derived public key must carry the P-256 curve tag.");

        //Blinding round-trip: Ybl = t*Y, G' = aU*G, Y'bl = aU*Ybl, Y' = t^-1*Y'bl. The result must equal aU*Y.
        using G1Point blindingPublicKey = Mul(generator, walletProviderKey, pool);   //G' = aU*G
        using G1Point blindSecdsaPublicKey = BlindRoundTrip(publicKey, blinding, walletProviderKey, pool);
        using(G1Point expected = Mul(publicKey, walletProviderKey, pool))
        {
            Assert.IsTrue(PointsEqual(expected, blindSecdsaPublicKey),
                "Y' = t^-1*aU*t*Y must equal aU*Y after the blinding round-trip.");
        }

        //-- SIGNING: the pool overload returns a tagged SecdsaSignature carrier (Algorithm 2) --
        byte[] messageHash = Digest("present-pid-attributes SN=1");
        using SecdsaSignature signature = SecdsaAlgorithm.SplitSign(
            pinKey.AsReadOnlySpan(), hardwareKey.AsReadOnlySpan(), messageHash, NonceSource,
            ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            SecdsaAlgorithm.Verify(
                publicKey.AsReadOnlySpan(), messageHash, signature.GetRBytes(), signature.GetSBytes(),
                ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add),
            "The split signature must verify under Y as ordinary ECDSA (Algorithm 14).");

        //Recover the full nonce point R = k*G the WSCA verification equation needs.
        Span<byte> noncePointBytes = stackalloc byte[CompressedSize];
        Assert.IsTrue(
            SecdsaAlgorithm.RecoverNoncePoint(
                publicKey.AsReadOnlySpan(), messageHash, signature.GetRBytes(), signature.GetSBytes(),
                ScalarMultiply, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, noncePointBytes),
            "The signature must yield a finite nonce point R.");
        using G1Point noncePoint = G1Point.FromCanonical(noncePointBytes, Curve, pool);

        //G'' = s^-1*G', Y'' = s^-1*Y' as tagged points; the blinding ZKP shares the witness s^-1 (Algorithm 3/4).
        using Scalar signatureScalar = Scalar.FromCanonical(signature.GetSBytes(), Curve, pool);
        using Scalar signatureInverse = Invert(signatureScalar, pool);
        using G1Point gDoublePrime = Mul(blindingPublicKey, signatureInverse, pool);
        using G1Point yDoublePrime = Mul(blindSecdsaPublicKey, signatureInverse, pool);

        using DlEqualityProof blindingProof = SecdsaEvidence.ProveBlindingRelation(
            blindingPublicKey.AsReadOnlySpan(), gDoublePrime.AsReadOnlySpan(),
            blindSecdsaPublicKey.AsReadOnlySpan(), yDoublePrime.AsReadOnlySpan(),
            signatureInverse.AsReadOnlySpan(), NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            SecdsaEvidence.VerifyBlindingRelation(
                blindingPublicKey.AsReadOnlySpan(), gDoublePrime.AsReadOnlySpan(),
                blindSecdsaPublicKey.AsReadOnlySpan(), yDoublePrime.AsReadOnlySpan(),
                blindingProof.GetRBytes(), blindingProof.GetSBytes(), Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The blind-signing relation proof must verify.");

        //-- WSCA VERIFICATION: R' = e*G'' + r*Y'' must equal aU*R (Proposition 3.3) --
        //
        //e is reduced from the message hash through FromBytesReduced; r is the signature component as a scalar.
        using Scalar e = Scalar.FromBytesReduced(messageHash, ScalarReduce, Curve, pool);
        using Scalar r = Scalar.FromCanonical(signature.GetRBytes(), Curve, pool);
        using G1Point verificationPoint = ComputeVerificationPoint(e, gDoublePrime, r, yDoublePrime, pool);
        using(G1Point expectedVerificationPoint = Mul(noncePoint, walletProviderKey, pool))
        {
            Assert.IsTrue(PointsEqual(expectedVerificationPoint, verificationPoint),
                "R' = e*G'' + r*Y'' must equal aU*R — the invariant proving the correct PIN was used.");
        }

        //-- CONTROL EVIDENCE: G' = aU*G and R' = aU*R share aU, bound to N = H(T_I) (Equation 7, Algorithm 9/10) --
        byte[] recordContext = Digest("transaction-record T_I for instruction #1");
        using DlEqualityProof controlProof = SecdsaEvidence.ProveControlRelation(
            generator.AsReadOnlySpan(), noncePoint.AsReadOnlySpan(), blindingPublicKey.AsReadOnlySpan(), verificationPoint.AsReadOnlySpan(),
            walletProviderKey.AsReadOnlySpan(), recordContext, NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            SecdsaEvidence.VerifyControlRelation(
                generator.AsReadOnlySpan(), noncePoint.AsReadOnlySpan(), blindingPublicKey.AsReadOnlySpan(), verificationPoint.AsReadOnlySpan(),
                recordContext, controlProof.GetRBytes(), controlProof.GetSBytes(), Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A third party must accept the wallet-provider control evidence bound to the transaction record.");
    }


    /// <summary>Derives <c>Y = (P·u)·G</c> as a tagged compressed point (Algorithm 1).</summary>
    private static G1Point DeriveSplitPublicKey(Scalar pinKey, Scalar hardwareKey, BaseMemoryPool pool)
    {
        Span<byte> publicKey = stackalloc byte[CompressedSize];
        SecdsaAlgorithm.DeriveSplitPublicKey(
            pinKey.AsReadOnlySpan(), hardwareKey.AsReadOnlySpan(), ScalarMultiply, G1ScalarMultiply, publicKey);

        return G1Point.FromCanonical(publicKey, Curve, pool);
    }


    /// <summary>Runs the blinding round-trip <c>Y' = t^-1·(aU·(t·Y))</c>, returning the blind SECDSA public key.</summary>
    private static G1Point BlindRoundTrip(G1Point publicKey, Scalar blinding, Scalar walletProviderKey, BaseMemoryPool pool)
    {
        using G1Point blinded = Mul(publicKey, blinding, pool);
        using G1Point blindedPrime = Mul(blinded, walletProviderKey, pool);
        using Scalar blindingInverse = Invert(blinding, pool);

        return Mul(blindedPrime, blindingInverse, pool);
    }


    /// <summary>Computes the WSCA verification point <c>R' = e·G'' + r·Y''</c> (Proposition 3.3).</summary>
    private static G1Point ComputeVerificationPoint(Scalar e, G1Point gDoublePrime, Scalar r, G1Point yDoublePrime, BaseMemoryPool pool)
    {
        using G1Point left = Mul(gDoublePrime, e, pool);
        using G1Point right = Mul(yDoublePrime, r, pool);

        return Add(left, right, pool);
    }


    /// <summary>Computes <c>factor·point</c> as a fresh tagged compressed point.</summary>
    private static G1Point Mul(G1Point point, Scalar factor, BaseMemoryPool pool)
    {
        Span<byte> result = stackalloc byte[CompressedSize];
        G1ScalarMultiply(point.AsReadOnlySpan(), factor.AsReadOnlySpan(), result, Curve);

        return G1Point.FromCanonical(result, Curve, pool);
    }


    /// <summary>Computes the curve sum <c>a + b</c> as a fresh tagged compressed point.</summary>
    private static G1Point Add(G1Point a, G1Point b, BaseMemoryPool pool)
    {
        Span<byte> result = stackalloc byte[CompressedSize];
        G1Add(a.AsReadOnlySpan(), b.AsReadOnlySpan(), result, Curve);

        return G1Point.FromCanonical(result, Curve, pool);
    }


    /// <summary>Computes <c>a^-1 mod n</c> as a fresh tagged scalar.</summary>
    private static Scalar Invert(Scalar a, BaseMemoryPool pool)
    {
        Span<byte> result = stackalloc byte[ScalarSize];
        ScalarInvert(a.AsReadOnlySpan(), result, Curve);

        return Scalar.FromCanonical(result, Curve, pool);
    }


    /// <summary>Compares two points by their canonical SEC1-compressed encoding.</summary>
    private static bool PointsEqual(G1Point left, G1Point right) =>
        left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());


    /// <summary>SHA-256 of an ASCII label, the 32-byte digest a message hash or transaction-record context needs.</summary>
    private static byte[] Digest(string label)
    {
        byte[] digest = new byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(label), digest);

        return digest;
    }


    /// <summary>The Fiat-Shamir hash the DL-equality evidence binds with — SHA-256.</summary>
    private static void Sha256FiatShamir(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        Sha256.HashData(input, output);
}
