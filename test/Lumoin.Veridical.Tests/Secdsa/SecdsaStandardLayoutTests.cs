using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Secdsa;
using Lumoin.Veritas.Cbor;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using static Lumoin.Veridical.Tests.Secdsa.SecdsaTestSupport;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the DER and CBOR layout profiles next to the provisional one: the full issue, respond and verify flow runs
/// under each, a value formed under one profile is rejected under any other, typed values convert losslessly between
/// every ordered pair while keeping the profile they were signed under, the encodings are injective, the decoders are
/// strict, and independent readers of the two standard formats find the same field values.
/// </summary>
[TestClass]
internal sealed class SecdsaStandardLayoutTests
{
    private const int DerCrossCheckKind = 6;

    private const int CborCrossCheckKind = 6;

    private const byte DerSequenceTag = 0x30;

    private const byte DerIndefiniteLength = 0x80;

    private const int DerLongFormFlag = 0x80;

    private const byte FixedDigestByte = 0x11;

    private const byte DerEndOfContentsOctet = 0x00;

    private const byte CborIndefiniteArray = 0x9F;

    private const byte CborBreak = 0xFF;

    private static SecdsaLayoutProfile Provisional { get; } = SecdsaProvisionalLayout.Profile;

    private static SecdsaLayoutProfile Der { get; } = SecdsaDerLayout.Profile;

    private static SecdsaLayoutProfile Cbor { get; } = SecdsaCborLayout.Profile;

    private static SecdsaLayoutProfile[] Profiles { get; } = [Provisional, Der, Cbor];


    [TestMethod]
    public void ProfileIdentifiersAreDistinct()
    {
        HashSet<string> identifiers = [];
        foreach(SecdsaLayoutProfile profile in Profiles)
        {
            Assert.IsTrue(identifiers.Add(profile.Id.Identifier));
        }
    }


    [TestMethod]
    public void IssueRespondVerifyAcceptsUnderEveryShippedProfile()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts flow");

        foreach(SecdsaLayoutProfile profile in Profiles)
        {
            AssertFlowAccepts(fixture, profile);
        }
    }


    [TestMethod]
    public void ValuesFormedUnderOneProfileAreRejectedUnderEveryOther()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts mismatch");

        foreach(SecdsaLayoutProfile signing in Profiles)
        {
            AssertRejectedUnderEveryOther(fixture, signing);
        }
    }


    [TestMethod]
    public void SignedScopeBytesDifferBetweenEveryPairOfProfiles()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts scopes");
        using IssuedChallenge issued = fixture.Issue();
        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        HashSet<string> scopes = [];
        foreach(SecdsaLayoutProfile profile in Profiles)
        {
            using LayoutWriter scope = new(fixture.Pool);
            profile.EncodeChallengeScope(ephemeral, fixture.Statement, secondary, scope);
            Assert.IsTrue(scopes.Add(Convert.ToHexString(scope.WrittenBytes)), "Two profiles produced the same signed bytes, so a signature would carry across them.");
        }
    }


    [TestMethod]
    public void TypedValuesConvertLosslesslyBetweenEveryOrderedPairOfProfiles()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts conversion");
        Span<byte> scalars = stackalloc byte[3 * ScalarSize];
        DeriveScalar("conversion scalar 0"u8, scalars[..ScalarSize]);
        DeriveScalar("conversion scalar 1"u8, scalars.Slice(ScalarSize, ScalarSize));
        DeriveScalar("conversion scalar 2"u8, scalars[(2 * ScalarSize)..]);
        using P256ScalarVector scalarVector = P256ScalarVector.FromCanonical(scalars, fixture.Pool);

        foreach(SecdsaLayoutProfile signing in Profiles)
        {
            AssertConvertsForEveryOrderedPair(fixture, scalarVector, signing);
        }
    }


    [TestMethod]
    public void AdditionalDataBoundaryShiftChangesTheBytesUnderEveryProfile()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts injective aad");
        using IssuedChallenge issued = fixture.Issue();
        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        using ProofDigest primary = ProofDigest.FromCanonical(secondary.GetBytes(), ProofDigestKind.Primary, fixture.Pool);

        foreach(SecdsaLayoutProfile profile in Profiles)
        {
            HashSet<string> encodings = [];
            ReadOnlySpan<byte> material = "aab"u8;
            for(int length = 0; length <= material.Length; length++)
            {
                using AdditionalData aad = AdditionalData.FromCanonical(material[..length], AdditionalDataRole.Authenticated, fixture.Pool);
                ProofStatement statement = new(fixture.Generators, fixture.PublicKeys, aad);
                using LayoutWriter challengeScope = new(fixture.Pool);
                using LayoutWriter responseScope = new(fixture.Pool);
                using LayoutWriter derivation = new(fixture.Pool);
                profile.EncodeChallengeScope(ephemeral, statement, secondary, challengeScope);
                profile.EncodeResponseScope(ephemeral, statement, secondary, primary, responseScope);
                profile.EncodeDerivationInput(0, statement, derivation);

                Assert.IsTrue(encodings.Add(Convert.ToHexString(challengeScope.WrittenBytes)), "Challenge scope collided.");
                Assert.IsTrue(encodings.Add(Convert.ToHexString(responseScope.WrittenBytes)), "Response scope collided.");
                Assert.IsTrue(encodings.Add(Convert.ToHexString(derivation.WrittenBytes)), "Derivation input collided.");
            }

            Assert.HasCount(4 * 3, encodings);
        }
    }


    [TestMethod]
    public void ContainerBoundaryShiftBetweenAdjacentVariableFieldsChangesTheBytesUnderEveryProfile()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts injective containers");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        ReadOnlySpan<byte> ephemeral = issued.Challenge.GetEphemeralPublicKeyBytes();
        ReadOnlySpan<byte> secondary = issued.Challenge.GetSecondaryDigestBytes();

        foreach(SecdsaLayoutProfile profile in Profiles)
        {
            AssertContainerBoundaryShifts(fixture, issued, prover, profile);
        }
    }


    [TestMethod]
    public void DifferentStructureKindsNeverEncodeToTheSameBytes()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts kinds");
        using IssuedChallenge issued = fixture.Issue();
        using ProverResponse? prover = fixture.Respond(issued);
        Assert.IsNotNull(prover);
        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        using ProofDigest primary = prover.Response.GetPrimaryDigest(fixture.Pool);
        Span<byte> scalars = stackalloc byte[ScalarSize];
        DeriveScalar("kinds scalar"u8, scalars);
        using P256ScalarVector scalarVector = P256ScalarVector.FromCanonical(scalars, fixture.Pool);

        foreach(SecdsaLayoutProfile profile in Profiles)
        {
            HashSet<string> encodings = [];
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeDerivationInput(0, fixture.Statement, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeChallengeScope(ephemeral, fixture.Statement, secondary, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeResponseScope(ephemeral, fixture.Statement, secondary, primary, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeSeedPayload(fixture.Seed, fixture.SecretData, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeCiphertext(issued.Ciphertext, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeChallenge(issued.Challenge, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeResponse(prover.Response, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodePointVector(fixture.Generators, writer));
            AddEncoding(encodings, fixture.Pool, writer => profile.EncodeScalarVector(scalarVector, writer));

            Assert.HasCount(9, encodings);
        }
    }


    [TestMethod]
    public void DerDecodersRejectMalformedWireData()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts der strict");
        using IssuedChallenge issued = fixture.Issue(Der);
        using ProverResponse? prover = fixture.Respond(issued, Der);
        Assert.IsNotNull(prover);
        using LayoutWriter challengeBytes = new(fixture.Pool);
        Der.EncodeChallenge(issued.Challenge, challengeBytes);
        using LayoutWriter responseBytes = new(fixture.Pool);
        Der.EncodeResponse(prover.Response, responseBytes);

        AssertStrictlyRejectsStructuralDamage(Der, challengeBytes.WrittenBytes, responseBytes.WrittenBytes, fixture.Pool);

        //The outer length re-encoded with an extra leading zero octet is a non-minimal length.
        Span<byte> widened = stackalloc byte[responseBytes.Length + 2];
        Assert.IsTrue(WidenDerLength(responseBytes.WrittenBytes, widened));
        Assert.IsFalse(DecodesResponse(Der, widened, fixture.Pool), "A non-minimal length must be rejected.");

        //The same content inside the long form that the short form could have carried.
        Span<byte> longForm = stackalloc byte[responseBytes.Length + 1];
        longForm[0] = DerSequenceTag;
        longForm[1] = 0x81;
        longForm[2] = responseBytes.WrittenBytes[1];
        responseBytes.WrittenBytes[2..].CopyTo(longForm[3..]);
        Assert.IsLessThan(0x80, responseBytes.WrittenBytes[1]);
        Assert.IsFalse(DecodesResponse(Der, longForm, fixture.Pool), "A long form below 128 must be rejected.");

        //A definite length replaced by the indefinite form with end-of-contents octets.
        Span<byte> indefinite = stackalloc byte[responseBytes.Length + 2];
        indefinite[0] = DerSequenceTag;
        indefinite[1] = DerIndefiniteLength;
        responseBytes.WrittenBytes[2..].CopyTo(indefinite[2..]);
        indefinite[^2] = DerEndOfContentsOctet;
        indefinite[^1] = DerEndOfContentsOctet;
        Assert.IsFalse(DecodesResponse(Der, indefinite, fixture.Pool), "An indefinite length must be rejected.");
    }


    [TestMethod]
    public void DerSeedPayloadDecoderIsStrictAboutIntegersAndTags()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts der payload");
        ReadOnlySpan<byte> seed = fixture.Seed.GetBytes();

        //30 27 | 02 01 04 | 04 20 seed | 04 00
        Span<byte> valid = stackalloc byte[2 + 3 + 2 + ProofSeed.SizeBytes + 2];
        valid[0] = DerSequenceTag;
        valid[1] = (byte)(valid.Length - 2);
        valid[2] = 0x02;
        valid[3] = 0x01;
        valid[4] = 0x04;
        valid[5] = 0x04;
        valid[6] = 0x20;
        seed.CopyTo(valid[7..]);
        valid[^2] = 0x04;
        valid[^1] = 0x00;
        Assert.IsTrue(DecodesPayload(Der, valid, fixture.Pool));

        Span<byte> nonMinimalInteger = stackalloc byte[valid.Length + 1];
        valid[..2].CopyTo(nonMinimalInteger);
        nonMinimalInteger[1] = (byte)(nonMinimalInteger.Length - 2);
        nonMinimalInteger[2] = 0x02;
        nonMinimalInteger[3] = 0x02;
        nonMinimalInteger[4] = 0x00;
        valid[4..].CopyTo(nonMinimalInteger[5..]);
        Assert.IsFalse(DecodesPayload(Der, nonMinimalInteger, fixture.Pool), "A redundant leading zero octet in an INTEGER must be rejected.");

        Span<byte> negative = stackalloc byte[valid.Length];
        valid.CopyTo(negative);
        negative[4] = 0x84;
        Assert.IsFalse(DecodesPayload(Der, negative, fixture.Pool), "A negative INTEGER must be rejected.");

        Span<byte> wrongKind = stackalloc byte[valid.Length];
        valid.CopyTo(wrongKind);
        wrongKind[4] = 0x05;
        Assert.IsFalse(DecodesPayload(Der, wrongKind, fixture.Pool), "A foreign discriminator must be rejected.");

        Span<byte> wrongTag = stackalloc byte[valid.Length];
        valid.CopyTo(wrongTag);
        wrongTag[5] = 0x0C;
        Assert.IsFalse(DecodesPayload(Der, wrongTag, fixture.Pool), "A UTF8String where an OCTET STRING is required must be rejected.");

        Span<byte> shortSeed = stackalloc byte[valid.Length - 1];
        valid[..6].CopyTo(shortSeed);
        shortSeed[1] = (byte)(shortSeed.Length - 2);
        shortSeed[6] = ProofSeed.SizeBytes - 1;
        seed[..(ProofSeed.SizeBytes - 1)].CopyTo(shortSeed[7..]);
        shortSeed[^2] = 0x04;
        shortSeed[^1] = 0x00;
        Assert.IsFalse(DecodesPayload(Der, shortSeed, fixture.Pool), "A seed that is not 32 octets must be rejected.");
    }


    [TestMethod]
    public void CborDecodersRejectMalformedWireData()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts cbor strict");
        using IssuedChallenge issued = fixture.Issue(Cbor);
        using ProverResponse? prover = fixture.Respond(issued, Cbor);
        Assert.IsNotNull(prover);
        using LayoutWriter challengeBytes = new(fixture.Pool);
        Cbor.EncodeChallenge(issued.Challenge, challengeBytes);
        using LayoutWriter responseBytes = new(fixture.Pool);
        Cbor.EncodeResponse(prover.Response, responseBytes);

        AssertStrictlyRejectsStructuralDamage(Cbor, challengeBytes.WrittenBytes, responseBytes.WrittenBytes, fixture.Pool);

        //The array head 0x84 re-encoded in the one-byte form is not the shortest form.
        Span<byte> widened = stackalloc byte[responseBytes.Length + 1];
        widened[0] = 0x98;
        widened[1] = (byte)(responseBytes.WrittenBytes[0] & 0x1F);
        responseBytes.WrittenBytes[1..].CopyTo(widened[2..]);
        Assert.IsFalse(DecodesResponse(Cbor, widened, fixture.Pool), "A non-shortest array head must be rejected.");

        //The array turned into an indefinite-length array.
        Span<byte> indefinite = stackalloc byte[responseBytes.Length + 1];
        indefinite[0] = CborIndefiniteArray;
        responseBytes.WrittenBytes[1..].CopyTo(indefinite[1..]);
        indefinite[^1] = CborBreak;
        Assert.IsFalse(DecodesResponse(Cbor, indefinite, fixture.Pool), "An indefinite-length array must be rejected.");
    }


    [TestMethod]
    public void CborSeedPayloadDecoderIsStrictAboutHeadsAndMajorTypes()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts cbor payload");
        ReadOnlySpan<byte> seed = fixture.Seed.GetBytes();

        //83 | 04 | 58 20 seed | 40
        Span<byte> valid = stackalloc byte[1 + 1 + 2 + ProofSeed.SizeBytes + 1];
        valid[0] = 0x83;
        valid[1] = 0x04;
        valid[2] = 0x58;
        valid[3] = 0x20;
        seed.CopyTo(valid[4..]);
        valid[^1] = 0x40;
        Assert.IsTrue(DecodesPayload(Cbor, valid, fixture.Pool));

        Span<byte> longSeedHead = stackalloc byte[valid.Length + 1];
        valid[..3].CopyTo(longSeedHead);
        longSeedHead[2] = 0x59;
        longSeedHead[3] = 0x00;
        valid[3..].CopyTo(longSeedHead[4..]);
        Assert.IsFalse(DecodesPayload(Cbor, longSeedHead, fixture.Pool), "A two-byte head for a value below 256 must be rejected.");

        Span<byte> longDiscriminator = stackalloc byte[valid.Length + 1];
        longDiscriminator[0] = 0x83;
        longDiscriminator[1] = 0x18;
        longDiscriminator[2] = 0x04;
        valid[2..].CopyTo(longDiscriminator[3..]);
        Assert.IsFalse(DecodesPayload(Cbor, longDiscriminator, fixture.Pool), "A one-byte head for a value below 24 must be rejected.");

        Span<byte> textSeed = stackalloc byte[valid.Length];
        valid.CopyTo(textSeed);
        textSeed[2] = 0x78;
        Assert.IsFalse(DecodesPayload(Cbor, textSeed, fixture.Pool), "A text string where a byte string is required must be rejected.");

        Span<byte> wrongCount = stackalloc byte[valid.Length];
        valid.CopyTo(wrongCount);
        wrongCount[0] = 0x82;
        Assert.IsFalse(DecodesPayload(Cbor, wrongCount, fixture.Pool), "A wrong element count must be rejected.");

        Span<byte> wrongKind = stackalloc byte[valid.Length];
        valid.CopyTo(wrongKind);
        wrongKind[1] = 0x05;
        Assert.IsFalse(DecodesPayload(Cbor, wrongKind, fixture.Pool), "A foreign discriminator must be rejected.");

        Span<byte> indefiniteString = stackalloc byte[valid.Length + 2];
        indefiniteString[0] = 0x83;
        indefiniteString[1] = 0x04;
        indefiniteString[2] = 0x5F;
        indefiniteString[3] = 0x58;
        indefiniteString[4] = 0x20;
        seed.CopyTo(indefiniteString[5..]);
        indefiniteString[^2] = CborBreak;
        indefiniteString[^1] = 0x40;
        Assert.IsFalse(DecodesPayload(Cbor, indefiniteString, fixture.Pool), "An indefinite-length byte string must be rejected.");
    }


    [TestMethod]
    public void DerOutputParsesWithTheFrameworkAsnReaderToTheSameFields()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts der cross check");
        using IssuedChallenge issued = fixture.Issue(Der);
        using ProverResponse? prover = fixture.Respond(issued, Der);
        Assert.IsNotNull(prover);

        using LayoutWriter challengeBytes = new(fixture.Pool);
        Der.EncodeChallenge(issued.Challenge, challengeBytes);
        using(IMemoryOwner<byte> owner = Copy(challengeBytes.WrittenBytes, fixture.Pool))
        {
            AsnReader outer = new(owner.Memory[..challengeBytes.Length], AsnEncodingRules.DER);
            AsnReader sequence = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            Assert.AreEqual(new BigInteger(DerCrossCheckKind), sequence.ReadInteger());
            Assert.AreEqual(issued.Challenge.Profile.Identifier, sequence.ReadCharacterString(UniversalTagNumber.UTF8String));
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(issued.Challenge.GetEphemeralPublicKeyBytes()));
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(issued.Challenge.GetSecondaryDigestBytes()));
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(issued.Challenge.GetAdditionalAuthenticatedDataBytes()));
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(issued.Challenge.GetSignatureBytes()));
            sequence.ThrowIfNotEmpty();
        }

        using LayoutWriter responseBytes = new(fixture.Pool);
        Der.EncodeResponse(prover.Response, responseBytes);
        using(IMemoryOwner<byte> owner = Copy(responseBytes.WrittenBytes, fixture.Pool))
        {
            AsnReader sequence = new AsnReader(owner.Memory[..responseBytes.Length], AsnEncodingRules.DER).ReadSequence();
            Assert.AreEqual(new BigInteger(7), sequence.ReadInteger());
            Assert.AreEqual(prover.Response.Profile.Identifier, sequence.ReadCharacterString(UniversalTagNumber.UTF8String));
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(prover.Response.GetPrimaryDigestBytes()));
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(prover.Response.GetSignatureBytes()));
            sequence.ThrowIfNotEmpty();
        }

        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        using LayoutWriter scopeBytes = new(fixture.Pool);
        Der.EncodeChallengeScope(ephemeral, fixture.Statement, secondary, scopeBytes);
        using(IMemoryOwner<byte> owner = Copy(scopeBytes.WrittenBytes, fixture.Pool))
        {
            AsnReader sequence = new AsnReader(owner.Memory[..scopeBytes.Length], AsnEncodingRules.DER).ReadSequence();
            Assert.AreEqual(new BigInteger(2), sequence.ReadInteger());
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(ephemeral.AsReadOnlySpan()));
            AssertDerPoints(sequence.ReadSequence(), fixture.Generators);
            AssertDerPoints(sequence.ReadSequence(), fixture.PublicKeys);
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(secondary.GetBytes()));
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(fixture.Statement.AdditionalAuthenticatedData.GetBytes()));
            sequence.ThrowIfNotEmpty();
        }

        using LayoutWriter derivationBytes = new(fixture.Pool);
        const int derivationIndex = 2;
        Der.EncodeDerivationInput(derivationIndex, fixture.Statement, derivationBytes);
        using(IMemoryOwner<byte> owner = Copy(derivationBytes.WrittenBytes, fixture.Pool))
        {
            AsnReader sequence = new AsnReader(owner.Memory[..derivationBytes.Length], AsnEncodingRules.DER).ReadSequence();
            Assert.AreEqual(new BigInteger(1), sequence.ReadInteger());
            Assert.AreEqual(new BigInteger(derivationIndex), sequence.ReadInteger());
            AssertDerPoints(sequence.ReadSequence(), fixture.Generators);
            AssertDerPoints(sequence.ReadSequence(), fixture.PublicKeys);
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(fixture.Statement.AdditionalAuthenticatedData.GetBytes()));
            sequence.ThrowIfNotEmpty();
        }
    }


    [TestMethod]
    public void DerIntegersUseTheMinimalFormAcrossTheIndexRange()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts der integers");
        int[] indexes = [0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536, 8388607, 8388608, int.MaxValue];
        foreach(int index in indexes)
        {
            using LayoutWriter writer = new(fixture.Pool);
            Der.EncodeDerivationInput(index, fixture.Statement, writer);
            using IMemoryOwner<byte> owner = Copy(writer.WrittenBytes, fixture.Pool);
            AsnReader sequence = new AsnReader(owner.Memory[..writer.Length], AsnEncodingRules.DER).ReadSequence();
            sequence.ReadInteger();
            Assert.AreEqual(new BigInteger(index), sequence.ReadInteger());
        }
    }


    [TestMethod]
    public void CborOutputReadsBackFieldByFieldInTheDocumentedOrder()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts cbor cross check");
        using IssuedChallenge issued = fixture.Issue(Cbor);
        using ProverResponse? prover = fixture.Respond(issued, Cbor);
        Assert.IsNotNull(prover);
        CborSerializerOptions options = new();

        using LayoutWriter challengeBytes = new(fixture.Pool);
        Cbor.EncodeChallenge(issued.Challenge, challengeBytes);
        using(IMemoryOwner<byte> owner = Copy(challengeBytes.WrittenBytes, fixture.Pool))
        {
            CborReader reader = new(owner.Memory[..challengeBytes.Length], options);
            Assert.AreEqual(6, reader.ReadStartArray());
            Assert.AreEqual((ulong)CborCrossCheckKind, reader.ReadUInt64());
            Assert.AreEqual(issued.Challenge.Profile.Identifier, reader.ReadTextString());
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(issued.Challenge.GetEphemeralPublicKeyBytes()));
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(issued.Challenge.GetSecondaryDigestBytes()));
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(issued.Challenge.GetAdditionalAuthenticatedDataBytes()));
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(issued.Challenge.GetSignatureBytes()));
            reader.ReadEndArray();
            Assert.AreEqual(challengeBytes.Length, reader.BytesConsumed);
        }

        using LayoutWriter responseBytes = new(fixture.Pool);
        Cbor.EncodeResponse(prover.Response, responseBytes);
        using(IMemoryOwner<byte> owner = Copy(responseBytes.WrittenBytes, fixture.Pool))
        {
            CborReader reader = new(owner.Memory[..responseBytes.Length], options);
            Assert.AreEqual(4, reader.ReadStartArray());
            Assert.AreEqual(7UL, reader.ReadUInt64());
            Assert.AreEqual(prover.Response.Profile.Identifier, reader.ReadTextString());
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(prover.Response.GetPrimaryDigestBytes()));
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(prover.Response.GetSignatureBytes()));
            reader.ReadEndArray();
            Assert.AreEqual(responseBytes.Length, reader.BytesConsumed);
        }

        using G1Point ephemeral = issued.Challenge.GetEphemeralPublicKey(fixture.Pool);
        using ProofDigest secondary = issued.Challenge.GetSecondaryDigest(fixture.Pool);
        using ProofDigest primary = prover.Response.GetPrimaryDigest(fixture.Pool);
        using LayoutWriter scopeBytes = new(fixture.Pool);
        Cbor.EncodeResponseScope(ephemeral, fixture.Statement, secondary, primary, scopeBytes);
        using(IMemoryOwner<byte> owner = Copy(scopeBytes.WrittenBytes, fixture.Pool))
        {
            CborReader reader = new(owner.Memory[..scopeBytes.Length], options);
            Assert.AreEqual(7, reader.ReadStartArray());
            Assert.AreEqual(3UL, reader.ReadUInt64());
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(ephemeral.AsReadOnlySpan()));
            AssertCborPoints(reader, fixture.Generators);
            AssertCborPoints(reader, fixture.PublicKeys);
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(secondary.GetBytes()));
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(fixture.Statement.AdditionalAuthenticatedData.GetBytes()));
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(primary.GetBytes()));
            reader.ReadEndArray();
            Assert.AreEqual(scopeBytes.Length, reader.BytesConsumed);
        }

        using LayoutWriter derivationBytes = new(fixture.Pool);
        const int derivationIndex = 70000;
        Cbor.EncodeDerivationInput(derivationIndex, fixture.Statement, derivationBytes);
        using(IMemoryOwner<byte> owner = Copy(derivationBytes.WrittenBytes, fixture.Pool))
        {
            CborReader reader = new(owner.Memory[..derivationBytes.Length], options);
            Assert.AreEqual(5, reader.ReadStartArray());
            Assert.AreEqual(1UL, reader.ReadUInt64());
            Assert.AreEqual((ulong)derivationIndex, reader.ReadUInt64());
            AssertCborPoints(reader, fixture.Generators);
            AssertCborPoints(reader, fixture.PublicKeys);
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(fixture.Statement.AdditionalAuthenticatedData.GetBytes()));
            reader.ReadEndArray();
            Assert.AreEqual(derivationBytes.Length, reader.BytesConsumed);
        }
    }


    [TestMethod]
    public void CborHeadsUseTheShortestFormAcrossTheIndexRange()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts cbor heads");
        (int Index, int HeadSize)[] cases = [(0, 1), (23, 1), (24, 2), (255, 2), (256, 3), (65535, 3), (65536, 5), (int.MaxValue, 5)];
        foreach((int index, int headSize) in cases)
        {
            using LayoutWriter writer = new(fixture.Pool);
            Cbor.EncodeDerivationInput(index, fixture.Statement, writer);

            //The array head and the discriminator take two bytes; the index head follows.
            ReadOnlySpan<byte> indexHead = writer.WrittenBytes[2..];
            Assert.AreEqual(headSize, HeadLength(indexHead[0]));
        }
    }


    [TestMethod]
    public void ResponseEncodesToTheHandDerivedBytesUnderDerAndCbor()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts fixed vectors");
        byte[] expectedDer = Convert.FromHexString("302C020107" + "0C0170" + "0420" + new string('1', 64) + "0402AABB");
        byte[] expectedCbor = Convert.FromHexString("84" + "07" + "6170" + "5820" + new string('1', 64) + "42AABB");
        SecdsaLayoutProfileId id = new("p");
        Span<byte> digestBytes = stackalloc byte[ProofDigest.SizeBytes];
        digestBytes.Fill(FixedDigestByte);
        ReadOnlySpan<byte> signature = [0xAA, 0xBB];
        using ProofDigest digest = ProofDigest.FromCanonical(digestBytes, ProofDigestKind.Primary, fixture.Pool);
        using TransferableResponse response = TransferableResponse.FromParts(digest, signature, id, fixture.Pool);

        using LayoutWriter derBytes = new(fixture.Pool);
        Der.EncodeResponse(response, derBytes);
        Assert.AreSequenceEqual(expectedDer, derBytes.WrittenBytes.ToArray());
        Assert.IsTrue(Der.DecodeResponse(expectedDer, fixture.Pool, out TransferableResponse? fromDer));
        using(fromDer)
        {
            Assert.AreEqual(id, fromDer!.Profile);
            Assert.IsTrue(fromDer.GetSignatureBytes().SequenceEqual(signature));
        }

        using LayoutWriter cborBytes = new(fixture.Pool);
        Cbor.EncodeResponse(response, cborBytes);
        Assert.AreSequenceEqual(expectedCbor, cborBytes.WrittenBytes.ToArray());
        Assert.IsTrue(Cbor.DecodeResponse(expectedCbor, fixture.Pool, out TransferableResponse? fromCbor));
        using(fromCbor)
        {
            Assert.AreEqual(id, fromCbor!.Profile);
            Assert.IsTrue(fromCbor.GetSignatureBytes().SequenceEqual(signature));
        }
    }


    [TestMethod]
    public void ScalarVectorEncodesToTheHandDerivedBytesUnderDerAndCbor()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts fixed vectors scalar");
        string scalarHex = new string('0', 62) + "01";
        byte[] expectedDer = Convert.FromHexString("3027" + "020109" + "3022" + "0420" + scalarHex);
        byte[] expectedCbor = Convert.FromHexString("82" + "09" + "81" + "5820" + scalarHex);
        Span<byte> scalar = stackalloc byte[P256ScalarVector.ScalarSizeBytes];
        scalar[^1] = 1;
        using P256ScalarVector vector = P256ScalarVector.FromCanonical(scalar, fixture.Pool);

        using LayoutWriter derBytes = new(fixture.Pool);
        Der.EncodeScalarVector(vector, derBytes);
        Assert.AreSequenceEqual(expectedDer, derBytes.WrittenBytes.ToArray());
        Assert.IsTrue(Der.DecodeScalarVector(expectedDer, fixture.Pool, out P256ScalarVector? fromDer));
        fromDer!.Dispose();

        using LayoutWriter cborBytes = new(fixture.Pool);
        Cbor.EncodeScalarVector(vector, cborBytes);
        Assert.AreSequenceEqual(expectedCbor, cborBytes.WrittenBytes.ToArray());
        Assert.IsTrue(Cbor.DecodeScalarVector(expectedCbor, fixture.Pool, out P256ScalarVector? fromCbor));
        fromCbor!.Dispose();
    }


    [TestMethod]
    public void DerivationIndexEncodesToTheHandDerivedIntegerUnderDerAndCbor()
    {
        using TransferableFixture fixture = TransferableFixture.Create("standard layouts fixed index");
        (int Index, string DerInteger, string CborHead)[] cases =
        [
            (0, "020100", "00"),
            (23, "020117", "17"),
            (127, "02017F", "187F"),
            (128, "02020080", "1880"),
            (255, "020200FF", "18FF"),
            (256, "02020100", "190100"),
            (32768, "0203008000", "198000"),
            (65536, "020301" + "0000", "1A00010000"),
            (int.MaxValue, "02047FFFFFFF", "1A7FFFFFFF")
        ];

        foreach((int index, string derInteger, string cborHead) in cases)
        {
            using LayoutWriter derBytes = new(fixture.Pool);
            Der.EncodeDerivationInput(index, fixture.Statement, derBytes);

            //Outer SEQUENCE header, then the discriminator INTEGER 1, then the index.
            string derHex = Convert.ToHexString(derBytes.WrittenBytes);
            int headerChars = (derBytes.WrittenBytes[1] < DerLongFormFlag ? 2 : 2 + (derBytes.WrittenBytes[1] & ~DerLongFormFlag)) * 2;
            Assert.IsTrue(derHex[headerChars..].StartsWith("020101" + derInteger, StringComparison.Ordinal), $"Index {index} under DER.");

            using LayoutWriter cborBytes = new(fixture.Pool);
            Cbor.EncodeDerivationInput(index, fixture.Statement, cborBytes);

            //Array head 0x85, discriminator 1, then the index head.
            Assert.IsTrue(Convert.ToHexString(cborBytes.WrittenBytes).StartsWith("8501" + cborHead, StringComparison.Ordinal), $"Index {index} under CBOR.");
        }
    }


    private static void AssertFlowAccepts(TransferableFixture fixture, SecdsaLayoutProfile profile)
    {
        using IssuedChallenge issued = fixture.Issue(profile);
        Assert.AreEqual(profile.Id, issued.Challenge.Profile);
        using ProverResponse? prover = fixture.Respond(issued, profile);
        Assert.IsNotNull(prover);
        Assert.AreEqual(profile.Id, prover.Response.Profile);
        Assert.IsTrue(prover.SecretData.GetBytes().SequenceEqual(fixture.SecretData.GetBytes()));
        Assert.AreEqual(TransferableProofVerdict.Accept, fixture.Verify(issued.Challenge, prover.Response, profile));
    }


    private static void AssertRejectedUnderEveryOther(TransferableFixture fixture, SecdsaLayoutProfile signing)
    {
        using IssuedChallenge issued = fixture.Issue(signing);
        using ProverResponse? prover = fixture.Respond(issued, signing);
        Assert.IsNotNull(prover);

        foreach(SecdsaLayoutProfile other in Profiles)
        {
            if(other.Id == signing.Id)
            {
                continue;
            }

            Assert.IsFalse(fixture.Responds(issued, other), $"A challenge signed under {signing.Id.Identifier} must not be answered under {other.Id.Identifier}.");
            Assert.AreEqual(
                TransferableProofVerdict.RejectProfileMismatch,
                fixture.Verify(issued.Challenge, prover.Response, other),
                $"A proof signed under {signing.Id.Identifier} must be rejected under {other.Id.Identifier}.");
        }
    }


    private static void AssertConvertsForEveryOrderedPair(TransferableFixture fixture, P256ScalarVector scalarVector, SecdsaLayoutProfile signing)
    {
        using IssuedChallenge issued = fixture.Issue(signing);
        using ProverResponse? prover = fixture.Respond(issued, signing);
        Assert.IsNotNull(prover);

        foreach(SecdsaLayoutProfile first in Profiles)
        {
            foreach(SecdsaLayoutProfile second in Profiles)
            {
                if(first.Id == second.Id)
                {
                    continue;
                }

                AssertConverts(fixture.Generators, first.EncodePointVector, first.DecodePointVector, second.EncodePointVector, second.DecodePointVector, fixture.Pool);
                AssertConverts(fixture.PublicKeys, first.EncodePointVector, first.DecodePointVector, second.EncodePointVector, second.DecodePointVector, fixture.Pool);
                AssertConverts(scalarVector, first.EncodeScalarVector, first.DecodeScalarVector, second.EncodeScalarVector, second.DecodeScalarVector, fixture.Pool);
                AssertConverts(issued.Challenge, first.EncodeChallenge, first.DecodeChallenge, second.EncodeChallenge, second.DecodeChallenge, fixture.Pool);
                AssertConverts(prover.Response, first.EncodeResponse, first.DecodeResponse, second.EncodeResponse, second.DecodeResponse, fixture.Pool);
                AssertCiphertextConverts(issued.Ciphertext, first, second, fixture.Pool);
                AssertSeedPayloadConverts(fixture, first, second);
                AssertConvertedProofStillVerifies(fixture, issued, prover, signing, first, second);
            }
        }
    }


    private static void AssertContainerBoundaryShifts(TransferableFixture fixture, IssuedChallenge issued, ProverResponse prover, SecdsaLayoutProfile profile)
    {
        ReadOnlySpan<byte> ephemeral = issued.Challenge.GetEphemeralPublicKeyBytes();
        ReadOnlySpan<byte> secondary = issued.Challenge.GetSecondaryDigestBytes();

        //AAD || Sig is "ab" || "cd" in both: only the boundary moves.
        using TransferableChallenge firstChallenge = fixture.Rebuild(issued.Challenge, ephemeral, secondary, "ab"u8, "cd"u8);
        using TransferableChallenge secondChallenge = fixture.Rebuild(issued.Challenge, ephemeral, secondary, "a"u8, "bcd"u8);
        using LayoutWriter firstChallengeBytes = new(fixture.Pool);
        using LayoutWriter secondChallengeBytes = new(fixture.Pool);
        profile.EncodeChallenge(firstChallenge, firstChallengeBytes);
        profile.EncodeChallenge(secondChallenge, secondChallengeBytes);
        Assert.IsFalse(firstChallengeBytes.WrittenBytes.SequenceEqual(secondChallengeBytes.WrittenBytes));

        //Profile identifier || signature is "idab" || "cd" in both: only the boundary moves.
        using TransferableResponse firstResponse = fixture.Rebuild(prover.Response, prover.Response.GetPrimaryDigestBytes(), "cd"u8, new SecdsaLayoutProfileId("idab"));
        using TransferableResponse secondResponse = fixture.Rebuild(prover.Response, prover.Response.GetPrimaryDigestBytes(), "d"u8, new SecdsaLayoutProfileId("idabc"));
        using LayoutWriter firstResponseBytes = new(fixture.Pool);
        using LayoutWriter secondResponseBytes = new(fixture.Pool);
        profile.EncodeResponse(firstResponse, firstResponseBytes);
        profile.EncodeResponse(secondResponse, secondResponseBytes);
        Assert.IsFalse(firstResponseBytes.WrittenBytes.SequenceEqual(secondResponseBytes.WrittenBytes));
    }


    private static int HeadLength(byte initial)
    {
        return (initial & 0x1F) switch
        {
            < 24 => 1,
            24 => 2,
            25 => 3,
            26 => 5,
            _ => 9
        };
    }


    private static void AssertDerPoints(AsnReader sequence, P256PointVector expected)
    {
        for(int index = 0; index < expected.Count; index++)
        {
            Assert.IsTrue(sequence.ReadOctetString().AsSpan().SequenceEqual(expected.GetPointBytes(index)));
        }

        sequence.ThrowIfNotEmpty();
    }


    private static void AssertCborPoints(CborReader reader, P256PointVector expected)
    {
        Assert.AreEqual(expected.Count, reader.ReadStartArray());
        for(int index = 0; index < expected.Count; index++)
        {
            Assert.IsTrue(reader.ReadByteString().AsSpan().SequenceEqual(expected.GetPointBytes(index)));
        }

        reader.ReadEndArray();
    }


    private static IMemoryOwner<byte> Copy(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return owner;
    }


    private static void AddEncoding(HashSet<string> encodings, BaseMemoryPool pool, Action<LayoutWriter> encode)
    {
        using LayoutWriter writer = new(pool);
        encode(writer);
        Assert.IsTrue(encodings.Add(Convert.ToHexString(writer.WrittenBytes)), "Two structure kinds encoded to the same bytes.");
    }


    /// <summary>Applies truncation, a trailing byte, a foreign outer tag and a foreign structure kind to a challenge and a response.</summary>
    private static void AssertStrictlyRejectsStructuralDamage(SecdsaLayoutProfile profile, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> response, BaseMemoryPool pool)
    {
        Assert.IsTrue(DecodesChallenge(profile, challenge, pool));
        Assert.IsTrue(DecodesResponse(profile, response, pool));
        Assert.IsFalse(DecodesChallenge(profile, challenge[..^1], pool), "A truncated challenge must be rejected.");
        Assert.IsFalse(DecodesResponse(profile, response[..^1], pool), "A truncated response must be rejected.");
        Assert.IsFalse(DecodesChallenge(profile, challenge[..1], pool));
        Assert.IsFalse(DecodesChallenge(profile, ReadOnlySpan<byte>.Empty, pool));

        Span<byte> trailing = stackalloc byte[challenge.Length + 1];
        challenge.CopyTo(trailing);
        Assert.IsFalse(DecodesChallenge(profile, trailing, pool), "A trailing byte must be rejected.");
        Span<byte> trailingResponse = stackalloc byte[response.Length + 1];
        response.CopyTo(trailingResponse);
        Assert.IsFalse(DecodesResponse(profile, trailingResponse, pool), "A trailing byte must be rejected.");

        //The same bytes read as the other kind of container.
        Assert.IsFalse(DecodesResponse(profile, challenge, pool), "A challenge must not decode as a response.");
        Assert.IsFalse(DecodesChallenge(profile, response, pool), "A response must not decode as a challenge.");

        Span<byte> foreignTag = stackalloc byte[response.Length];
        response.CopyTo(foreignTag);
        foreignTag[0] ^= 0x01;
        Assert.IsFalse(DecodesResponse(profile, foreignTag, pool), "A wrong outer tag or major type must be rejected.");
    }


    private static bool DecodesChallenge(SecdsaLayoutProfile profile, ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        bool decoded = profile.DecodeChallenge(bytes, pool, out TransferableChallenge? challenge);
        challenge?.Dispose();

        return decoded;
    }


    private static bool DecodesResponse(SecdsaLayoutProfile profile, ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        bool decoded = profile.DecodeResponse(bytes, pool, out TransferableResponse? response);
        response?.Dispose();

        return decoded;
    }


    private static bool DecodesPayload(SecdsaLayoutProfile profile, ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        bool decoded = profile.DecodeSeedPayload(bytes, pool, out ProofSeed? seed, out AdditionalData? data);
        seed?.Dispose();
        data?.Dispose();

        return decoded;
    }


    /// <summary>Rewrites the outer SEQUENCE length of a DER encoding with one extra leading zero octet.</summary>
    private static bool WidenDerLength(ReadOnlySpan<byte> encoded, Span<byte> widened)
    {
        int first = encoded[1];
        if(first < 0x80)
        {
            widened[0] = encoded[0];
            widened[1] = 0x82;
            widened[2] = 0x00;
            widened[3] = (byte)first;
            encoded[2..].CopyTo(widened[4..]);

            return widened.Length >= encoded.Length + 2;
        }

        return false;
    }


    private static void AssertConverts<T>(
        T value,
        LayoutEncodeDelegate<T> encodeFirst,
        LayoutDecodeDelegate<T> decodeFirst,
        LayoutEncodeDelegate<T> encodeSecond,
        LayoutDecodeDelegate<T> decodeSecond,
        BaseMemoryPool pool)
        where T : SensitiveMemory
    {
        using LayoutWriter firstBytes = new(pool);
        encodeFirst(value, firstBytes);
        Assert.IsTrue(decodeFirst(firstBytes.WrittenBytes, pool, out T? viaFirst));
        using(viaFirst)
        {
            Assert.IsTrue(viaFirst!.AsReadOnlySpan().SequenceEqual(value.AsReadOnlySpan()), "Decoding the first layout must give the value back.");

            using LayoutWriter secondBytes = new(pool);
            encodeSecond(viaFirst, secondBytes);
            Assert.IsFalse(secondBytes.WrittenBytes.SequenceEqual(firstBytes.WrittenBytes), "The two layouts must differ.");
            Assert.IsTrue(decodeSecond(secondBytes.WrittenBytes, pool, out T? viaSecond));
            using(viaSecond)
            {
                Assert.IsTrue(viaSecond!.AsReadOnlySpan().SequenceEqual(value.AsReadOnlySpan()), "Converting to the second layout must be lossless.");
                if(value is TransferableChallenge challenge && viaSecond is TransferableChallenge convertedChallenge)
                {
                    Assert.AreEqual(challenge.Profile, convertedChallenge.Profile, "A converted challenge keeps the profile it was signed under.");
                }

                if(value is TransferableResponse response && viaSecond is TransferableResponse convertedResponse)
                {
                    Assert.AreEqual(response.Profile, convertedResponse.Profile, "A converted response keeps the profile it was signed under.");
                }
            }
        }
    }


    private static void AssertCiphertextConverts(EciesCiphertext ciphertext, SecdsaLayoutProfile first, SecdsaLayoutProfile second, BaseMemoryPool pool)
    {
        using LayoutWriter firstBytes = new(pool);
        first.EncodeCiphertext(ciphertext, firstBytes);
        Assert.IsTrue(first.DecodeCiphertext(firstBytes.WrittenBytes, TransferableFixture.Parameters, pool, out EciesCiphertext? viaFirst));
        using(viaFirst)
        {
            using LayoutWriter secondBytes = new(pool);
            second.EncodeCiphertext(viaFirst!, secondBytes);
            Assert.IsFalse(secondBytes.WrittenBytes.SequenceEqual(firstBytes.WrittenBytes));
            Assert.IsTrue(second.DecodeCiphertext(secondBytes.WrittenBytes, TransferableFixture.Parameters, pool, out EciesCiphertext? viaSecond));
            using(viaSecond)
            {
                Assert.IsTrue(viaSecond!.AsReadOnlySpan().SequenceEqual(ciphertext.AsReadOnlySpan()));
            }
        }
    }


    private static void AssertSeedPayloadConverts(TransferableFixture fixture, SecdsaLayoutProfile first, SecdsaLayoutProfile second)
    {
        using LayoutWriter firstBytes = new(fixture.Pool);
        first.EncodeSeedPayload(fixture.Seed, fixture.SecretData, firstBytes);
        Assert.IsTrue(first.DecodeSeedPayload(firstBytes.WrittenBytes, fixture.Pool, out ProofSeed? seed, out AdditionalData? data));
        using(seed)
        using(data)
        {
            using LayoutWriter secondBytes = new(fixture.Pool);
            second.EncodeSeedPayload(seed!, data!, secondBytes);
            Assert.IsFalse(secondBytes.WrittenBytes.SequenceEqual(firstBytes.WrittenBytes));
            Assert.IsTrue(second.DecodeSeedPayload(secondBytes.WrittenBytes, fixture.Pool, out ProofSeed? seedBack, out AdditionalData? dataBack));
            using(seedBack)
            using(dataBack)
            {
                Assert.IsTrue(seedBack!.GetBytes().SequenceEqual(fixture.Seed.GetBytes()));
                Assert.IsTrue(dataBack!.GetBytes().SequenceEqual(fixture.SecretData.GetBytes()));
            }
        }
    }


    /// <summary>
    /// A challenge and response carried through the transport layout of <paramref name="second"/>, and a statement
    /// rebuilt from vectors carried through it, still verify under the profile they were signed under.
    /// </summary>
    private static void AssertConvertedProofStillVerifies(
        TransferableFixture fixture,
        IssuedChallenge issued,
        ProverResponse prover,
        SecdsaLayoutProfile signing,
        SecdsaLayoutProfile first,
        SecdsaLayoutProfile second)
    {
        using LayoutWriter challengeBytes = new(fixture.Pool);
        second.EncodeChallenge(issued.Challenge, challengeBytes);
        using LayoutWriter responseBytes = new(fixture.Pool);
        second.EncodeResponse(prover.Response, responseBytes);
        using LayoutWriter generatorBytes = new(fixture.Pool);
        first.EncodePointVector(fixture.Generators, generatorBytes);
        using LayoutWriter publicKeyBytes = new(fixture.Pool);
        second.EncodePointVector(fixture.PublicKeys, publicKeyBytes);

        Assert.IsTrue(second.DecodeChallenge(challengeBytes.WrittenBytes, fixture.Pool, out TransferableChallenge? challenge));
        Assert.IsTrue(second.DecodeResponse(responseBytes.WrittenBytes, fixture.Pool, out TransferableResponse? response));
        Assert.IsTrue(first.DecodePointVector(generatorBytes.WrittenBytes, fixture.Pool, out P256PointVector? generators));
        Assert.IsTrue(second.DecodePointVector(publicKeyBytes.WrittenBytes, fixture.Pool, out P256PointVector? publicKeys));
        using(challenge)
        using(response)
        using(generators)
        using(publicKeys)
        {
            Assert.AreEqual(signing.Id, challenge!.Profile);
            Assert.AreEqual(signing.Id, response!.Profile);
            ProofStatement statement = new(generators!, publicKeys!, fixture.AuthenticatedData);
            Assert.AreEqual(TransferableProofVerdict.Accept, fixture.Verify(challenge, response, signing, statement));
        }
    }
}
