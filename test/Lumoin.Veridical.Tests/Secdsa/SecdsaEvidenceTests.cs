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
/// Gates for <see cref="SecdsaEvidence"/>, the convenience instantiations of the DL-equality NIZK for SECDSA's two
/// relations: the blind-signing relation (Verheul Algorithm 3 Steps 6–7, Algorithm 4 Step 10) and the wallet-provider control relation
/// (Equation (7), Algorithms 9/10). The second test walks the publicly-verifiable evidence flow end-to-end — the
/// cryptographic core of the transparency evidence a wallet provider logs.
/// </summary>
[TestClass]
internal sealed class SecdsaEvidenceTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static ScalarAddDelegate ScalarAdd { get; } = P256BigIntegerScalarReference.GetAdd();
    private static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static G1AddDelegate G1Add { get; } = P256BigIntegerG1Reference.GetAdd();
    private static G1NegateDelegate G1Negate { get; } = P256BigIntegerG1Reference.GetNegate();

    private static SecdsaNonceSource NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);
    private static FiatShamirHashDelegate Hash { get; } = Sha256FiatShamir;


    [TestMethod]
    public void BlindingRelationRoundTrips()
    {
        //Verheul Algorithm 3 Steps 6-7: the wallet proves G'' = s^-1*G and Y'' = s^-1*Y' (the signature was correctly
        //blinded) without revealing s^-1; G is the standard base point and Y' comes from the internal certificate.
        byte[] blindingWitness = DeriveScalar("blinding-s-inverse");
        byte[] g = Generator();
        byte[] yPrime = ScalarMul(Generator(), DeriveScalar("cert-y-prime"));
        byte[] gDoublePrime = ScalarMul(g, blindingWitness);
        byte[] yDoublePrime = ScalarMul(yPrime, blindingWitness);

        using var pool = new BaseMemoryPool();
        using DlEqualityProof proof = SecdsaEvidence.ProveBlindingRelationSpan(
            g, gDoublePrime, yPrime, yDoublePrime, blindingWitness,
            NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        byte[] r = proof.GetRBytes().ToArray();
        byte[] s = proof.GetSBytes().ToArray();

        Assert.IsTrue(
            SecdsaEvidence.VerifyBlindingRelationSpan(g, gDoublePrime, yPrime, yDoublePrime, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The blind-signing relation proof must verify.");

        //A G'' that is not s^-1*G (a different blinding) must be rejected.
        byte[] wrongGDoublePrime = ScalarMul(g, DeriveScalar("wrong-blinding"));
        Assert.IsFalse(
            SecdsaEvidence.VerifyBlindingRelationSpan(g, wrongGDoublePrime, yPrime, yDoublePrime, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A mis-formed G'' must be rejected.");
    }


    [TestMethod]
    public void WalletProviderControlEvidenceIsPubliclyVerifiable()
    {
        //FLOW DEMONSTRATION (cryptographic core of Verheul Equation (7) / Algorithms 9-10 evidence).
        //The wallet provider holds a blinding key aU and the internal certificate holds H' = aU*H on the
        //wallet-specific base point H. For the point W = R - e*G'' of an instruction the provider publishes
        //W' = aU*W and proves the CONTROL relation ZKP[(H,H'),(W,W'),H(T_I)], so ANY third party (a judge,
        //mediator, or relying party) can confirm it used aU correctly and consistently WITHOUT learning aU. This
        //proof, bound to the transaction-record context H(T_I), is the publicly-verifiable evidence the provider
        //records. The interactive and transferable variants (Protocol 2 / Algorithms 22-24), the record
        //signature, the transparency log, and PID issuance are the application layer.
        byte[] blindingKey = DeriveScalar("wallet-provider-blinding-key-aU");
        byte[] h = ScalarMul(Generator(), DeriveScalar("wallet-specific-base-point-H"));
        byte[] w = ScalarMul(Generator(), DeriveScalar("instruction-point-W"));
        byte[] hPrime = ScalarMul(h, blindingKey);  //H' = aU*H
        byte[] wPrime = ScalarMul(w, blindingKey);  //W' = aU*W
        byte[] recordContext = TranscriptHash("transaction-record T_I for instruction #42");

        using var pool = new BaseMemoryPool();
        using DlEqualityProof evidence = SecdsaEvidence.ProveControlRelationSpan(
            h, w, hPrime, wPrime, blindingKey, recordContext,
            NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        byte[] r = evidence.GetRBytes().ToArray();
        byte[] s = evidence.GetSBytes().ToArray();

        Assert.IsTrue(
            SecdsaEvidence.VerifyControlRelationSpan(h, w, hPrime, wPrime, recordContext, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A third party must accept the wallet-provider control evidence.");

        //A provider that applied a DIFFERENT key to W (forged W') cannot produce verifiable evidence against H'.
        byte[] forgedWPrime = ScalarMul(w, DeriveScalar("a-different-key"));
        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelationSpan(h, w, hPrime, forgedWPrime, recordContext, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "Evidence over a W' formed with a different key must be rejected.");

        //The evidence is bound to its transaction-record context: a different record must not accept it.
        byte[] otherContext = TranscriptHash("transaction-record T_I for instruction #43");
        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelationSpan(h, w, hPrime, wPrime, otherContext, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "Evidence must not verify against a different transaction-record context.");
    }


    [TestMethod]
    public void VerifyControlRelationRejectsMalformedPointWithoutThrowing()
    {
        //A structurally malformed point (wrong length) arriving from the wire must reject, not throw.
        byte[] h = Generator();
        byte[] w = ScalarMul(Generator(), DeriveScalar("W"));
        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        byte[] truncated = new byte[ScalarSize]; //32 bytes, not a 33-byte compressed point.

        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelationSpan(h, w, truncated, w, [], r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A wrong-length point must be rejected without throwing.");
    }


    private static byte[] Generator()
    {
        byte[] generator = new byte[CompressedSize];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.P256).CopyTo(generator);

        return generator;
    }


    private static byte[] ScalarMul(byte[] point, byte[] scalar)
    {
        byte[] result = new byte[CompressedSize];
        G1ScalarMultiply(point, scalar, result, CurveParameterSet.P256);

        return result;
    }


    private static byte[] DeriveScalar(string label)
    {
        byte[] digest = new byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(label), digest);
        byte[] scalar = new byte[ScalarSize];
        ScalarReduce(digest, scalar, CurveParameterSet.P256);

        return scalar;
    }


    private static byte[] TranscriptHash(string record)
    {
        byte[] hash = new byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(record), hash);

        return hash;
    }


    private static void Sha256FiatShamir(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        Sha256.HashData(input, output);
}
