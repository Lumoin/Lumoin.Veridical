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
/// Gates for the typed entry points of <see cref="DlEqualityNizk"/> and <see cref="SecdsaEvidence"/>: the witness is a
/// <see cref="PrivateScalar"/>, generator and public-key lists are <see cref="P256PointVector"/>, relation points are
/// <see cref="G1Point"/>, contexts are <see cref="AdditionalData"/> and the proof is a <see cref="DlEqualityProof"/>.
/// </summary>
[TestClass]
internal sealed class SecdsaEvidenceTypedTests
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
    public void TypedDlEqualityProofRoundTripsAndBindsTheContext()
    {
        using var pool = new BaseMemoryPool();
        byte[] witnessBytes = DeriveScalar("typed-dleq-witness");
        byte[] secondBase = ScalarMul(Generator(), DeriveScalar("typed-dleq-second-base"));
        byte[] generatorsBytes = [.. Generator(), .. secondBase];
        byte[] publicKeysBytes = [.. ScalarMul(Generator(), witnessBytes), .. ScalarMul(secondBase, witnessBytes)];

        using PrivateScalar witness = PrivateScalar.FromCanonical(witnessBytes, pool);
        using P256PointVector generators = P256PointVector.FromCanonical(generatorsBytes, pool);
        using P256PointVector publicKeys = P256PointVector.FromCanonical(publicKeysBytes, pool);
        using AdditionalData challenge = AdditionalData.FromCanonical(Encoding.ASCII.GetBytes("typed-challenge"), AdditionalDataRole.Authenticated, pool);
        using AdditionalData otherChallenge = AdditionalData.FromCanonical(Encoding.ASCII.GetBytes("other-challenge"), AdditionalDataRole.Authenticated, pool);

        using DlEqualityProof proof = DlEqualityNizk.Prove(
            witness, generators, publicKeys, challenge, NonceSource, Hash,
            ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            DlEqualityNizk.Verify(generators, publicKeys, challenge, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The typed proof must verify under the context it was bound to.");
        Assert.IsFalse(
            DlEqualityNizk.Verify(generators, publicKeys, otherChallenge, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The typed proof must not verify under a different context.");
    }


    [TestMethod]
    public void TypedBlindingRelationRoundTripsAndRejectsAMisformedPoint()
    {
        using var pool = new BaseMemoryPool();
        byte[] witnessBytes = DeriveScalar("typed-blinding-witness");
        byte[] gBytes = Generator();
        byte[] yPrimeBytes = ScalarMul(gBytes, DeriveScalar("typed-cert-y-prime"));

        using PrivateScalar witness = PrivateScalar.FromCanonical(witnessBytes, pool);
        using G1Point g = Point(gBytes, pool);
        using G1Point gDoublePrime = Point(ScalarMul(gBytes, witnessBytes), pool);
        using G1Point yPrime = Point(yPrimeBytes, pool);
        using G1Point yDoublePrime = Point(ScalarMul(yPrimeBytes, witnessBytes), pool);
        using G1Point wrongGDoublePrime = Point(ScalarMul(gBytes, DeriveScalar("typed-wrong-blinding")), pool);

        using DlEqualityProof proof = SecdsaEvidence.ProveBlindingRelation(
            g, gDoublePrime, yPrime, yDoublePrime, witness,
            NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            SecdsaEvidence.VerifyBlindingRelation(g, gDoublePrime, yPrime, yDoublePrime, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The typed blind-signing relation proof must verify.");
        Assert.IsFalse(
            SecdsaEvidence.VerifyBlindingRelation(g, wrongGDoublePrime, yPrime, yDoublePrime, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A mis-formed G'' must be rejected.");
    }


    [TestMethod]
    public void TypedControlRelationRoundTripsAndBindsTheRecordContext()
    {
        using var pool = new BaseMemoryPool();
        byte[] witnessBytes = DeriveScalar("typed-control-witness");
        byte[] hBytes = ScalarMul(Generator(), DeriveScalar("typed-base-h"));
        byte[] wBytes = ScalarMul(Generator(), DeriveScalar("typed-point-w"));

        using PrivateScalar witness = PrivateScalar.FromCanonical(witnessBytes, pool);
        using G1Point h = Point(hBytes, pool);
        using G1Point w = Point(wBytes, pool);
        using G1Point hPrime = Point(ScalarMul(hBytes, witnessBytes), pool);
        using G1Point wPrime = Point(ScalarMul(wBytes, witnessBytes), pool);
        using G1Point forgedWPrime = Point(ScalarMul(wBytes, DeriveScalar("typed-forged")), pool);
        using AdditionalData recordContext = AdditionalData.FromCanonical(Encoding.ASCII.GetBytes("record T_I"), AdditionalDataRole.Authenticated, pool);
        using AdditionalData otherContext = AdditionalData.FromCanonical(Encoding.ASCII.GetBytes("other record"), AdditionalDataRole.Authenticated, pool);

        using DlEqualityProof proof = SecdsaEvidence.ProveControlRelation(
            h, w, hPrime, wPrime, witness, recordContext,
            NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool);

        Assert.IsTrue(
            SecdsaEvidence.VerifyControlRelation(h, w, hPrime, wPrime, recordContext, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The typed control relation proof must verify under its record context.");
        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelation(h, w, hPrime, forgedWPrime, recordContext, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A forged W' must be rejected.");
        Assert.IsFalse(
            SecdsaEvidence.VerifyControlRelation(h, w, hPrime, wPrime, otherContext, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A different record context must be rejected.");
    }


    [TestMethod]
    public void TypedEntryPointsRejectNullArguments()
    {
        using var pool = new BaseMemoryPool();
        using P256PointVector vector = P256PointVector.FromCanonical(Generator(), pool);
        using AdditionalData context = AdditionalData.FromCanonical([], AdditionalDataRole.Authenticated, pool);
        using DlEqualityProof proof = DlEqualityProof.FromCanonical(OneOne(), pool);

        Assert.ThrowsExactly<ArgumentNullException>(
            () => DlEqualityNizk.Verify(null!, vector, context, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate));
        Assert.ThrowsExactly<ArgumentNullException>(
            () => DlEqualityNizk.Verify(vector, vector, null!, proof, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate));
        Assert.ThrowsExactly<ArgumentNullException>(
            () => DlEqualityNizk.Verify(vector, vector, context, null!, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate));
    }


    private static byte[] OneOne()
    {
        byte[] bytes = new byte[ScalarSize * 2];
        bytes[ScalarSize - 1] = 1;
        bytes[(ScalarSize * 2) - 1] = 1;

        return bytes;
    }


    private static G1Point Point(byte[] compressed, BaseMemoryPool pool) =>
        G1Point.FromCanonical(compressed, CurveParameterSet.P256, pool);


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


    private static void Sha256FiatShamir(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        Sha256.HashData(input, output);
}
