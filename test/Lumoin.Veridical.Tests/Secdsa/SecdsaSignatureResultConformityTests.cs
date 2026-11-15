using Lumoin.Veridical.Core;
using Lumoin.Veridical.Secdsa;
using System;
using System.Buffers;
using static Lumoin.Veridical.Tests.Secdsa.SecdsaTestSupport;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the zero-knowledge signature-result conformity check of Verheul Annex F (Algorithm 41), built over
/// a SECDSA split signature so the user key is the composite key <c>Q_U = (P·u)·G</c>. The valid record must pass
/// with no alarm; every verification step has a record that fails it: a tampered proof (step 2), a blinded point
/// not formed from the claimed scalar (step 2), a wrong nonce point, a wrong message and a wrong user key
/// (steps 2 and 3), and malformed points (structural).
/// </summary>
[TestClass]
internal sealed class SecdsaSignatureResultConformityTests
{
    [TestMethod]
    public void ValidSignatureProducesRecordThatRaisesNoAlarm()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        SignatureResultConformity verdict = Check(fixture.Record, fixture.MessageHash, fixture.UserPublicKey);

        Assert.AreEqual(SignatureResultConformity.NoAlarm, verdict);
        Assert.AreEqual(SecdsaStructureKind.SignatureResultRecord, fixture.Record.Tag.Get<SecdsaStructureKind>());
    }


    [TestMethod]
    public void RecordDoesNotContainTheSignatureScalar()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        Assert.AreEqual(
            -1,
            fixture.Record.AsReadOnlySpan().IndexOf(fixture.Signature.GetSBytes()),
            "The record must not carry s, so a holder of the record cannot present the signature.");
        Assert.IsTrue(
            fixture.Record.GetNoncePointBytes()[1..].SequenceEqual(fixture.Signature.GetRBytes()),
            "r is the x-coordinate of R, which the record carries by design; s is the only part the record omits.");
    }


    [TestMethod]
    public void RecordSurvivesCanonicalRoundTrip()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        using SignatureResultRecord copy = SignatureResultRecord.FromCanonical(fixture.Record.AsReadOnlySpan(), pool);

        Assert.IsTrue(copy.AsReadOnlySpan().SequenceEqual(fixture.Record.AsReadOnlySpan()));
        Assert.AreEqual(SignatureResultConformity.NoAlarm, Check(copy, fixture.MessageHash, fixture.UserPublicKey));
        using DlEqualityProof proof = copy.GetProof(pool);
        Assert.IsTrue(proof.GetRBytes().SequenceEqual(copy.GetProofRBytes()));
    }


    [TestMethod]
    public void TamperedProofIsRejectedAtStepTwo()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        using SignatureResultRecord tampered = fixture.WithByteFlipped(SignatureResultRecord.ProofOffset + DlEqualityProof.ROffset, pool);

        Assert.AreEqual(SignatureResultConformity.AlarmProofRejected, Check(tampered, fixture.MessageHash, fixture.UserPublicKey));
    }


    [TestMethod]
    public void BlindedPointsNotFormedFromTheClaimedScalarAreRejectedAtStepTwo()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        //Q_U'' replaced by a point with a different discrete logarithm: the proof no longer covers the pair.
        Span<byte> two = stackalloc byte[ScalarSize];
        FillTwo(two);
        Span<byte> other = stackalloc byte[PointSize];
        Multiply(fixture.Record.GetBlindedPublicKeyBytes(), two, other);
        using SignatureResultRecord forged = fixture.WithRange(SignatureResultRecord.BlindedPublicKeyOffset, other, pool);

        Assert.AreEqual(SignatureResultConformity.AlarmProofRejected, Check(forged, fixture.MessageHash, fixture.UserPublicKey));
    }


    [TestMethod]
    public void WrongNoncePointIsRejectedAtStepThree()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        //The proof does not cover R, so a substituted R passes step 2 and fails the equation of step 3.
        Span<byte> two = stackalloc byte[ScalarSize];
        FillTwo(two);
        Span<byte> other = stackalloc byte[PointSize];
        Multiply(fixture.Record.GetNoncePointBytes(), two, other);
        using SignatureResultRecord forged = fixture.WithRange(SignatureResultRecord.NoncePointOffset, other, pool);

        Assert.AreEqual(SignatureResultConformity.AlarmResultMismatch, Check(forged, fixture.MessageHash, fixture.UserPublicKey));
    }


    [TestMethod]
    public void SignatureOnADifferentMessageRaisesAlarm()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        Span<byte> otherMessage = stackalloc byte[DigestSize];
        MessageHash("a message the instruction did not fix"u8, otherMessage);

        Assert.AreEqual(SignatureResultConformity.AlarmResultMismatch, Check(fixture.Record, otherMessage, fixture.UserPublicKey));
    }


    [TestMethod]
    public void WrongUserPublicKeyRaisesAlarm()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        Span<byte> scalar = stackalloc byte[ScalarSize];
        DeriveScalar("another user key"u8, scalar);
        Span<byte> otherKey = stackalloc byte[PointSize];
        PublicPoint(scalar, otherKey);

        Assert.AreEqual(SignatureResultConformity.AlarmProofRejected, Check(fixture.Record, fixture.MessageHash, otherKey));
    }


    [TestMethod]
    public void SignatureByAnotherKeyUnderTheRecordedBlindedPairRaisesAlarm()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        //A second user key signs the same message; the record built for it does not conform to the first key.
        using Fixture second = Fixture.Create(pool, "second pin key"u8, "second hardware key"u8);

        Assert.AreEqual(SignatureResultConformity.AlarmProofRejected, Check(second.Record, fixture.MessageHash, fixture.UserPublicKey));
    }


    [TestMethod]
    public void MalformedPointsRaiseAlarmWithoutThrowing()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        Span<byte> offCurve = stackalloc byte[PointSize];
        offCurve.Clear();
        offCurve[0] = 0x02;
        offCurve[^1] = 0x01;
        using SignatureResultRecord offCurveNonce = fixture.WithRange(SignatureResultRecord.NoncePointOffset, offCurve, pool);
        Assert.AreEqual(SignatureResultConformity.AlarmMalformedRecord, Check(offCurveNonce, fixture.MessageHash, fixture.UserPublicKey));

        Assert.ThrowsExactly<ArgumentException>(() => WithInfinityGenerator(fixture, pool));

        Assert.AreEqual(SignatureResultConformity.AlarmMalformedRecord, Check(fixture.Record, fixture.MessageHash[..(DigestSize - 1)], fixture.UserPublicKey));
        Assert.AreEqual(SignatureResultConformity.AlarmMalformedRecord, Check(fixture.Record, fixture.MessageHash, fixture.UserPublicKey[..(PointSize - 1)]));
    }


    [TestMethod]
    public void ProverRefusesASignatureThatDoesNotVerify()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        Assert.ThrowsExactly<ArgumentException>(() => ProveOnAnotherMessage(fixture, pool));
    }


    [TestMethod]
    public void RecordContainerRejectsWrongLengthAndZeroResponse()
    {
        using var pool = new BaseMemoryPool();
        using Fixture fixture = Fixture.Create(pool);

        Assert.ThrowsExactly<ArgumentException>(() => SignatureResultRecord.FromCanonical(fixture.Record.AsReadOnlySpan()[..(SignatureResultRecord.SizeBytes - 1)], pool));
        Assert.ThrowsExactly<ArgumentException>(() => WithZeroProofResponse(fixture, pool));
    }


    private static SignatureResultRecord ProveOnAnotherMessage(Fixture fixture, BaseMemoryPool pool)
    {
        Span<byte> otherMessage = stackalloc byte[DigestSize];
        MessageHash("not the signed message"u8, otherMessage);

        return SecdsaSignatureResultConformity.Prove(
            fixture.Signature, otherMessage, fixture.UserPublicKey,
            NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, pool);
    }


    private static SignatureResultRecord WithInfinityGenerator(Fixture fixture, BaseMemoryPool pool)
    {
        Span<byte> infinity = stackalloc byte[PointSize];
        infinity.Clear();

        return fixture.WithRange(SignatureResultRecord.BlindedGeneratorOffset, infinity, pool);
    }


    private static SignatureResultRecord WithZeroProofResponse(Fixture fixture, BaseMemoryPool pool)
    {
        Span<byte> zero = stackalloc byte[DlEqualityProof.SSizeBytes];
        zero.Clear();

        return fixture.WithRange(SignatureResultRecord.ProofOffset + DlEqualityProof.SOffset, zero, pool);
    }


    private static void FillTwo(Span<byte> scalar)
    {
        scalar.Clear();
        scalar[^1] = 0x02;
    }


    private static SignatureResultConformity Check(SignatureResultRecord record, ReadOnlySpan<byte> messageHash, ReadOnlySpan<byte> userPublicKey)
    {
        return SecdsaSignatureResultConformity.Check(record, messageHash, userPublicKey, Hash, ScalarReduce, G1ScalarMultiply, G1Add, G1Negate);
    }


    /// <summary>A split signature, the user key it verifies under, and the record built for it.</summary>
    private sealed class Fixture: IDisposable
    {
        private IMemoryOwner<byte> Material { get; }

        private Fixture(SecdsaSignature signature, SignatureResultRecord record, IMemoryOwner<byte> material)
        {
            Signature = signature;
            Record = record;
            Material = material;
        }

        public SecdsaSignature Signature { get; }

        public SignatureResultRecord Record { get; }

        public ReadOnlySpan<byte> MessageHash => Material.Memory.Span[..DigestSize];

        public ReadOnlySpan<byte> UserPublicKey => Material.Memory.Span.Slice(DigestSize, PointSize);


        public static Fixture Create(BaseMemoryPool pool)
        {
            return Create(pool, "secdsa conformity pin key"u8, "secdsa conformity hardware key"u8);
        }


        public static Fixture Create(BaseMemoryPool pool, ReadOnlySpan<byte> pinLabel, ReadOnlySpan<byte> hardwareLabel)
        {
            Span<byte> pin = stackalloc byte[ScalarSize];
            Span<byte> hardware = stackalloc byte[ScalarSize];
            DeriveScalar(pinLabel, pin);
            DeriveScalar(hardwareLabel, hardware);
            IMemoryOwner<byte> material = pool.Rent(DigestSize + PointSize);
            Span<byte> messageHash = material.Memory.Span[..DigestSize];
            Span<byte> userPublicKey = material.Memory.Span.Slice(DigestSize, PointSize);
            SecdsaTestSupport.MessageHash("transfer 100 EUR to the payee"u8, messageHash);

            SecdsaSignature signature = SecdsaAlgorithm.SplitSign(
                pin, hardware, messageHash, NonceSource,
                ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, pool);
            SecdsaAlgorithm.DeriveSplitPublicKey(pin, hardware, ScalarMultiply, G1ScalarMultiply, userPublicKey);

            SignatureResultRecord record = SecdsaSignatureResultConformity.Prove(
                signature, messageHash, userPublicKey,
                NonceSource, Hash, ScalarMultiply, ScalarAdd, ScalarInvert, ScalarReduce, G1ScalarMultiply, G1Add, pool);
            pin.Clear();
            hardware.Clear();

            return new Fixture(signature, record, material);
        }


        public SignatureResultRecord WithByteFlipped(int offset, BaseMemoryPool pool)
        {
            Span<byte> copy = stackalloc byte[SignatureResultRecord.SizeBytes];
            Record.AsReadOnlySpan().CopyTo(copy);
            copy[offset] ^= 0x01;

            return SignatureResultRecord.FromCanonical(copy, pool);
        }


        public SignatureResultRecord WithRange(int offset, ReadOnlySpan<byte> replacement, BaseMemoryPool pool)
        {
            Span<byte> copy = stackalloc byte[SignatureResultRecord.SizeBytes];
            Record.AsReadOnlySpan().CopyTo(copy);
            replacement.CopyTo(copy[offset..]);

            return SignatureResultRecord.FromCanonical(copy, pool);
        }


        public void Dispose()
        {
            Signature.Dispose();
            Record.Dispose();
            Material.Dispose();
        }
    }
}
