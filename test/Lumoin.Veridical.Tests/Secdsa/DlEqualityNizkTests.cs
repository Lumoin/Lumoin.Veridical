using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for <see cref="DlEqualityNizk"/>, Verheul's Schnorr/Chaum–Pedersen discrete-log-equality NIZK
/// (Algorithms 19/20) over NIST P-256. The proof attests statement (9) — that every <c>(G_i, D_i)</c> pair
/// shares one private key <c>d</c> (<c>D_i = d·G_i</c>) — in zero knowledge. The arithmetic is wired from the
/// BigInteger references; the SHA-256 Fiat–Shamir hash enters as an injected delegate so a caller chooses the
/// hasher.
/// </summary>
[TestClass]
internal sealed class DlEqualityNizkTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;

    private static ScalarMultiplyDelegate ScalarMultiply { get; } = P256BigIntegerScalarReference.GetMultiply();
    private static ScalarAddDelegate ScalarAdd { get; } = P256BigIntegerScalarReference.GetAdd();
    private static ScalarReduceDelegate ScalarReduce { get; } = P256BigIntegerScalarReference.GetReduce();
    private static ScalarSubtractDelegate ScalarSubtract { get; } = P256BigIntegerScalarReference.GetSubtract();
    private static G1ScalarMultiplyDelegate G1ScalarMultiply { get; } = P256BigIntegerG1Reference.GetScalarMultiply();
    private static G1AddDelegate G1Add { get; } = P256BigIntegerG1Reference.GetAdd();
    private static G1NegateDelegate G1Negate { get; } = P256BigIntegerG1Reference.GetNegate();

    private static SecdsaNonceSource NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);
    private static FiatShamirHashDelegate Hash { get; } = Sha256FiatShamir;

    private static BigInteger Order { get; } = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);


    [TestMethod]
    public void HonestProofOverEqualDiscreteLogsVerifies()
    {
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");
        byte[] challengeN = Encoding.ASCII.GetBytes("transaction-evidence-context");

        (byte[] r, byte[] s) = Prove(witness, generators, publicKeys, challengeN);

        Assert.IsTrue(Verify(generators, publicKeys, challengeN, r, s), "An honest DL-equality proof must verify.");

        //r is a non-zero full-width value; s is a scalar in [1, n-1].
        Assert.IsFalse(IsZero(r), "r must be non-zero.");
        BigInteger sInt = new(s, isUnsigned: true, isBigEndian: true);
        Assert.IsTrue(sInt >= BigInteger.One && sInt < Order, "s must be in [1, n-1].");
    }


    [TestMethod]
    public void ProofWithEmptyChallengeVerifies()
    {
        //SECDSA blind signing invokes the NIZK with N = empty; the empty-challenge path must round-trip.
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");

        (byte[] r, byte[] s) = Prove(witness, generators, publicKeys, []);

        Assert.IsTrue(Verify(generators, publicKeys, [], r, s), "A proof bound to an empty challenge must verify.");
    }


    [TestMethod]
    public void TamperedProofOrStatementIsRejectedWithoutThrowing()
    {
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");
        byte[] challengeN = Encoding.ASCII.GetBytes("ctx");

        (byte[] r, byte[] s) = Prove(witness, generators, publicKeys, challengeN);

        Assert.IsFalse(Verify(generators, publicKeys, challengeN, Flip(r), s), "A tampered r must be rejected.");
        Assert.IsFalse(Verify(generators, publicKeys, challengeN, r, Flip(s)), "A tampered s must be rejected.");
        Assert.IsFalse(Verify(Flip(generators), publicKeys, challengeN, r, s), "A tampered generator must be rejected.");
        Assert.IsFalse(Verify(generators, Flip(publicKeys), challengeN, r, s), "A tampered public key must be rejected.");
        Assert.IsFalse(Verify(generators, publicKeys, Encoding.ASCII.GetBytes("ctX"), r, s), "A changed challenge must be rejected.");
    }


    [TestMethod]
    public void FalseStatementDoesNotVerify()
    {
        //Soundness: D_0 = d·G_0 but D_1 = d'·G_1 with d' != d, so the two pairs have NO common discrete log. A
        //prover knowing d (which satisfies pair 0) cannot produce a proof that verifies the joint statement.
        byte[] witness = DeriveScalar("dleq-witness");
        byte[] otherWitness = DeriveScalar("dleq-other-witness");

        byte[] g0 = Generator();
        byte[] g1 = ScalarMul(Generator(), DeriveScalar("dleq-second-base"));
        byte[] generators = Concat(g0, g1);
        byte[] publicKeysFalse = Concat(ScalarMul(g0, witness), ScalarMul(g1, otherWitness));

        (byte[] r, byte[] s) = Prove(witness, generators, publicKeysFalse, []);

        Assert.IsFalse(Verify(generators, publicKeysFalse, [], r, s), "A false equal-discrete-log statement must not verify.");
    }


    [TestMethod]
    public void FullWidthChallengeIsStoredAndComparedUnreduced()
    {
        //The single most important interop point: r is the RAW Fiat–Shamir digest, never reduced mod n. A
        //natural transcript whose digest exceeds n is ~2^-32 to find, so a stub hash returns a fixed value above
        //n (all-ones = 2^256-1 > n). The proof must store that raw value, verify against it, and REJECT its
        //mod-n reduction — proving the comparison is full-width.
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");

        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        DlEqualityNizk.Prove(
            witness, generators, publicKeys, [], NonceSource, BigStubHash,
            ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, r, s);

        byte[] allOnes = new byte[ScalarSize];
        allOnes.AsSpan().Fill(0xFF);
        Assert.IsTrue(r.AsSpan().SequenceEqual(allOnes), "r must be stored as the raw full-width digest, not reduced mod n.");

        byte[] rReduced = new byte[ScalarSize];
        ScalarReduce(r, rReduced, CurveParameterSet.P256);
        Assert.IsFalse(rReduced.AsSpan().SequenceEqual(r), "The raw r exceeds n, so reduction changes it — confirming full-width matters.");

        Assert.IsTrue(
            DlEqualityNizk.Verify(generators, publicKeys, [], r, s, BigStubHash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "The full-width r must verify.");
        Assert.IsFalse(
            DlEqualityNizk.Verify(generators, publicKeys, [], rReduced, s, BigStubHash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate),
            "A mod-n-reduced r must NOT verify; the comparison is on the full-width value.");
    }


    [TestMethod]
    public void SinglePairProofOfPossessionVerifies()
    {
        //n = 0 in the paper's indexing: one pair (G_0, D_0 = d·G_0), a Schnorr proof of possession of d.
        byte[] witness = DeriveScalar("dleq-witness");
        byte[] g0 = Generator();
        byte[] generators = g0;
        byte[] publicKeys = ScalarMul(g0, witness);

        (byte[] r, byte[] s) = Prove(witness, generators, publicKeys, []);

        Assert.IsTrue(Verify(generators, publicKeys, [], r, s), "A single-pair proof of possession must verify.");
        Assert.IsFalse(Verify(generators, Flip(publicKeys), [], r, s), "A tampered single public key must be rejected.");
    }


    [TestMethod]
    public void VerifyRejectsDegenerateInputsWithoutThrowing()
    {
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");
        (byte[] r, byte[] s) = Prove(witness, generators, publicKeys, []);

        byte[] zero = new byte[ScalarSize];
        byte[] orderBytes = OrderBytes();
        byte[] infinity = new byte[CompressedSize]; //0x00 prefix => point at infinity.

        Assert.IsFalse(Verify(generators, publicKeys, [], zero, s), "r = 0 must be rejected.");
        Assert.IsFalse(Verify(generators, publicKeys, [], r, zero), "s = 0 must be rejected.");
        Assert.IsFalse(Verify(generators, publicKeys, [], r, orderBytes), "s = n must be rejected.");
        Assert.IsFalse(Verify(Concat(infinity, generators.AsSpan(CompressedSize)), publicKeys, [], r, s), "An identity generator must be rejected.");
        Assert.IsFalse(Verify(generators, Concat(infinity, publicKeys.AsSpan(CompressedSize)), [], r, s), "An identity public key must be rejected.");
    }


    [TestMethod]
    public void ProveThrowsWhenChallengeIsZero()
    {
        //A stub hash forcing r = 0 must surface as the documented degenerate-proof exception, not a silent proof.
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");

        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        Assert.ThrowsExactly<InvalidOperationException>(
            () => DlEqualityNizk.Prove(
                witness, generators, publicKeys, [], NonceSource, ZeroStubHash,
                ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, r, s),
            "A Fiat–Shamir challenge of zero must throw.");
    }


    [TestMethod]
    public void PooledProofIsClearedOnDispose()
    {
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");

        using var pool = new BaseMemoryPool();

        using(DlEqualityProof proof = DlEqualityNizk.Prove(
            witness, generators, publicKeys, [], NonceSource, Hash,
            ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, pool))
        {
            Assert.IsTrue(
                Verify(generators, publicKeys, [], proof.GetRBytes().ToArray(), proof.GetSBytes().ToArray()),
                "The pooled proof must verify.");
        }

        using IMemoryOwner<byte> rerented = pool.Rent(DlEqualityProof.SizeBytes);
        int firstNonZero = rerented.Memory.Span[..DlEqualityProof.SizeBytes].IndexOfAnyExcept((byte)0);
        Assert.AreEqual(-1, firstNonZero, "The returned proof buffer must be cleared.");
    }


    [TestMethod]
    public void ProofIsDeterministicForTheSameInputs()
    {
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");
        byte[] challengeN = Encoding.ASCII.GetBytes("ctx");

        (byte[] firstR, byte[] firstS) = Prove(witness, generators, publicKeys, challengeN);
        (byte[] secondR, byte[] secondS) = Prove(witness, generators, publicKeys, challengeN);

        Assert.IsTrue(firstR.AsSpan().SequenceEqual(secondR), "Proving the same statement twice must be deterministic in r.");
        Assert.IsTrue(firstS.AsSpan().SequenceEqual(secondS), "Proving the same statement twice must be deterministic in s.");
    }


    [TestMethod]
    public void DistinctStatementsUnderOneWitnessUseDifferentNonces()
    {
        //Regression for the unframed-nonce witness-recovery flaw. Two DISTINCT but honestly-true statements over
        //the SAME witness whose BARE concatenations collide (statement A: 1 pair, N = D0||D1; statement B: 2 pairs,
        //N = empty; both reduce to g0||e0||d0||d1) must derive DIFFERENT nonces k — else two responses over one k
        //recover the witness via d = (sA - sB)·((rA mod n) - (rB mod n))^-1. k is reconstructed as s - (r mod n)·d.
        byte[] d = DeriveScalar("dleq-witness");
        byte[] g0 = Generator();
        byte[] e0 = ScalarMul(g0, d);   //e0 = d*g0
        byte[] d0 = ScalarMul(g0, d);   //d0 = d*g0 (= e0)
        byte[] d1 = ScalarMul(e0, d);   //d1 = d*e0

        //A: one pair (g0, e0), challenge N = d0||d1.
        byte[] genA = g0;
        byte[] pkA = e0;
        byte[] challengeA = Concat(d0, d1);

        //B: two pairs (g0, e0)/(d0, d1), empty challenge. Bare concat g0||e0||d0||d1 matches A's bare concat.
        byte[] genB = Concat(g0, e0);
        byte[] pkB = Concat(d0, d1);

        (byte[] rA, byte[] sA) = Prove(d, genA, pkA, challengeA);
        (byte[] rB, byte[] sB) = Prove(d, genB, pkB, []);

        byte[] kA = ReconstructNonce(sA, rA, d);
        byte[] kB = ReconstructNonce(sB, rB, d);

        Assert.IsFalse(kA.AsSpan().SequenceEqual(kB), "Two distinct statements over one witness must not share a commitment nonce.");

        //Both must still verify under their own statements.
        Assert.IsTrue(Verify(genA, pkA, challengeA, rA, sA), "Statement A proof must verify.");
        Assert.IsTrue(Verify(genB, pkB, [], rB, sB), "Statement B proof must verify.");
    }


    [TestMethod]
    public void ChallengeBindingIsExclusive()
    {
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");
        byte[] challengeN = Encoding.ASCII.GetBytes("bound-context");

        (byte[] r, byte[] s) = Prove(witness, generators, publicKeys, challengeN);
        Assert.IsFalse(Verify(generators, publicKeys, [], r, s), "A proof bound to N must not verify with an empty challenge.");

        (byte[] r2, byte[] s2) = Prove(witness, generators, publicKeys, []);
        Assert.IsFalse(Verify(generators, publicKeys, challengeN, r2, s2), "A proof bound to an empty challenge must not verify under N.");
    }


    [TestMethod]
    public void ValidButWrongPointIsRejected()
    {
        //A tamper that yields a VALID on-curve point (D_0 + G) must reject via the algebraic check, not merely the
        //point decoder — pinning the transcript/equation binding rather than encoding validation.
        byte[] witness = DeriveScalar("dleq-witness");
        (byte[] generators, byte[] publicKeys) = TwoPairStatement(witness, "dleq-second-base");
        (byte[] r, byte[] s) = Prove(witness, generators, publicKeys, []);

        byte[] shiftedD0 = new byte[CompressedSize];
        G1Add(publicKeys.AsSpan(0, CompressedSize), Generator(), shiftedD0, CurveParameterSet.P256);
        byte[] wrongPublicKeys = Concat(shiftedD0, publicKeys.AsSpan(CompressedSize));

        Assert.IsFalse(Verify(generators, wrongPublicKeys, [], r, s), "A valid-but-wrong public key must be rejected.");
    }


    [TestMethod]
    public void ReorderedPairsAreRejected()
    {
        //The transcript binds pair ORDER: an asymmetric two-pair statement verified with its pairs swapped (same
        //proof) must reject.
        byte[] witness = DeriveScalar("dleq-witness");
        byte[] g0 = Generator();
        byte[] g1 = ScalarMul(Generator(), DeriveScalar("dleq-second-base"));
        byte[] d0 = ScalarMul(g0, witness);
        byte[] d1 = ScalarMul(g1, witness);

        (byte[] r, byte[] s) = Prove(witness, Concat(g0, g1), Concat(d0, d1), []);

        Assert.IsFalse(Verify(Concat(g1, g0), Concat(d1, d0), [], r, s), "Swapping the pair order must reject the proof.");
    }


    private static (byte[] R, byte[] S) Prove(byte[] witness, byte[] generators, byte[] publicKeys, byte[] challengeN)
    {
        byte[] r = new byte[ScalarSize];
        byte[] s = new byte[ScalarSize];
        DlEqualityNizk.Prove(
            witness, generators, publicKeys, challengeN, NonceSource, Hash,
            ScalarMultiply, ScalarAdd, ScalarReduce, G1ScalarMultiply, r, s);

        return (r, s);
    }


    private static bool Verify(byte[] generators, byte[] publicKeys, byte[] challengeN, byte[] r, byte[] s) =>
        DlEqualityNizk.Verify(generators, publicKeys, challengeN, r, s, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate);


    //Builds a two-pair statement (G_0 = G, G_1 = h·G) with both public keys D_i = witness·G_i.
    private static (byte[] Generators, byte[] PublicKeys) TwoPairStatement(byte[] witness, string secondBaseLabel)
    {
        byte[] g0 = Generator();
        byte[] g1 = ScalarMul(Generator(), DeriveScalar(secondBaseLabel));
        byte[] generators = Concat(g0, g1);
        byte[] publicKeys = Concat(ScalarMul(g0, witness), ScalarMul(g1, witness));

        return (generators, publicKeys);
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


    //k = s - (r mod n)*d mod n, the standard Schnorr nonce reconstruction from a response.
    private static byte[] ReconstructNonce(byte[] s, byte[] r, byte[] witness)
    {
        byte[] rModN = new byte[ScalarSize];
        ScalarReduce(r, rModN, CurveParameterSet.P256);
        byte[] rd = new byte[ScalarSize];
        ScalarMultiply(rModN, witness, rd, CurveParameterSet.P256);
        byte[] k = new byte[ScalarSize];
        ScalarSubtract(s, rd, k, CurveParameterSet.P256);

        return k;
    }


    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        byte[] result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));

        return result;
    }


    private static byte[] Flip(byte[] value)
    {
        byte[] copy = (byte[])value.Clone();
        copy[^1] ^= 0x01;

        return copy;
    }


    //A deterministic, in-range scalar in [1, n-1]: SHA-256 of the label reduced modulo n.
    private static byte[] DeriveScalar(string label)
    {
        byte[] digest = new byte[ScalarSize];
        Sha256.HashData(Encoding.ASCII.GetBytes(label), digest);
        byte[] scalar = new byte[ScalarSize];
        ScalarReduce(digest, scalar, CurveParameterSet.P256);

        return scalar;
    }


    private static byte[] OrderBytes()
    {
        byte[] big = Order.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] order = new byte[ScalarSize];
        big.CopyTo(order.AsSpan(ScalarSize - big.Length));

        return order;
    }


    private static bool IsZero(byte[] value) => value.AsSpan().IndexOfAnyExcept((byte)0) < 0;


    private static void Sha256FiatShamir(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        Sha256.HashData(input, output);


    //A stub Fiat–Shamir hash returning a fixed value above the group order (all-ones = 2^256-1 > n), used to
    //pin the full-width-r behaviour without searching ~2^32 transcripts for a natural digest exceeding n.
    private static void BigStubHash(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        output.Fill(0xFF);


    //A stub Fiat–Shamir hash returning zero, used to drive the r = 0 degenerate path.
    private static void ZeroStubHash(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) =>
        output.Clear();
}
