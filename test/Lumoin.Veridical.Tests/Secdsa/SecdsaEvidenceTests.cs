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
/// relations: the blind-signing relation (Verheul Algorithm 3/4) and the wallet-provider control relation
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
        //Verheul Algorithm 3/4: the wallet proves G'' = s^-1*G' and Y'' = s^-1*Y' (the signature was correctly
        //blinded) without revealing s^-1.
        byte[] blindingWitness = DeriveScalar("blinding-s-inverse");
        byte[] gPrime = ScalarMul(Generator(), DeriveScalar("cert-g-prime"));
        byte[] yPrime = ScalarMul(Generator(), DeriveScalar("cert-y-prime"));
        byte[] gDoublePrime = ScalarMul(gPrime, blindingWitness);
        byte[] yDoublePrime = ScalarMul(yPrime, blindingWitness);

        using var pool = new BaseMemoryPool();
        using DlEqualityProof proof = SecdsaEvidence.ProveBlindingRelation(
            gPrime, gDoublePrime, yPrime, yDoublePrime, blindingWitness,
            NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        byte[] r = proof.GetRBytes().ToArray();
        byte[] s = proof.GetSBytes().ToArray();

        Assert.IsTrue(
            SecdsaEvidence.VerifyBlindingRelation(gPrime, gDoublePrime, yPrime, yDoublePrime, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The blind-signing relation proof must verify.");

        //A G'' that is not s^-1*G' (a different blinding) must be rejected.
        byte[] wrongGDoublePrime = ScalarMul(gPrime, DeriveScalar("wrong-blinding"));
        Assert.IsFalse(
            SecdsaEvidence.VerifyBlindingRelation(gPrime, wrongGDoublePrime, yPrime, yDoublePrime, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A mis-formed G'' must be rejected.");
    }


    [TestMethod]
    public void WalletProviderControlEvidenceIsPubliclyVerifiable()
    {
        //FLOW DEMONSTRATION (cryptographic core of Verheul Equation (7) / Algorithms 9-10 evidence).
        //The wallet provider holds a blinding key aU. Applying it to the signature nonce point R it publishes
        //R' = aU*R, and via G' = aU*G it proves the CONTROL relation so ANY third party (a judge, mediator, or
        //relying party) can confirm it used aU correctly and consistently WITHOUT learning aU. This proof, bound
        //to the transaction-record context H(T_I), is the publicly-verifiable evidence the provider records.
        //The transferable variant (Protocol 2 / Algorithms 21-23), the record signature, the transparency log,
        //and PID issuance are the application layer (VerifableSystem).
        byte[] blindingKey = DeriveScalar("wallet-provider-blinding-key-aU");
        byte[] generator = Generator();
        byte[] noncePoint = ScalarMul(Generator(), DeriveScalar("signature-nonce-point-R"));
        byte[] blindedGenerator = ScalarMul(generator, blindingKey);   //G' = aU*G
        byte[] blindedNoncePoint = ScalarMul(noncePoint, blindingKey); //R' = aU*R
        byte[] recordContext = TranscriptHash("transaction-record T_I for instruction #42");

        using var pool = new BaseMemoryPool();
        using DlEqualityProof evidence = SecdsaEvidence.ProveControlRelation(
            generator, noncePoint, blindedGenerator, blindedNoncePoint, blindingKey, recordContext,
            NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        byte[] r = evidence.GetRBytes().ToArray();
        byte[] s = evidence.GetSBytes().ToArray();

        Assert.IsTrue(
            SecdsaEvidence.VerifyControlRelation(generator, noncePoint, blindedGenerator, blindedNoncePoint, recordContext, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A third party must accept the wallet-provider control evidence.");

        //A provider that applied a DIFFERENT key to R (forged R') cannot produce verifiable evidence against G'.
        byte[] forgedNoncePoint = ScalarMul(noncePoint, DeriveScalar("a-different-key"));
        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelation(generator, noncePoint, blindedGenerator, forgedNoncePoint, recordContext, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "Evidence over an R' formed with a different key must be rejected.");

        //The evidence is bound to its transaction-record context: a different record must not accept it.
        byte[] otherContext = TranscriptHash("transaction-record T_I for instruction #43");
        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelation(generator, noncePoint, blindedGenerator, blindedNoncePoint, otherContext, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "Evidence must not verify against a different transaction-record context.");
    }


    [TestMethod]
    public void VerifyControlRelationRejectsMalformedPointWithoutThrowing()
    {
        //A structurally malformed point (wrong length) arriving from the wire must reject, not throw.
        byte[] generator = Generator();
        byte[] noncePoint = ScalarMul(Generator(), DeriveScalar("R"));
        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        byte[] truncated = new byte[ScalarSize]; //32 bytes, not a 33-byte compressed point.

        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelation(generator, noncePoint, truncated, noncePoint, [], r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
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
