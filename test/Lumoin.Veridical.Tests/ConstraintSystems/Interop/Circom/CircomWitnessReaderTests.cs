using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// Conformance tests for the Circom <c>.wtns</c> reader, plus the
/// end-to-end gate that combines the parsed <c>.r1cs</c> and parsed
/// <c>.wtns</c> through both Spartan provers.
/// </summary>
[TestClass]
internal sealed class CircomWitnessReaderTests
{
    [TestMethod]
    public void Multiplier2WitnessParsesIntoExpectedValues()
    {
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);

        //RawR1csWitness contains z[1..nWitness] = (c, a, b) = (33, 3, 11)
        //in canonical big-endian, 32 bytes each. (The constant z[0] = 1
        //is dropped by the reader per the CircomWitnessReader convention.)
        Assert.AreEqual(3, witness.WitnessVariableCount);

        ReadOnlySpan<byte> bytes = witness.GetWitnessBytes();
        int scalarSize = WellKnownCurves.Bls12Curve381ScalarSizeBytes;
        Assert.AreEqual(3 * scalarSize, bytes.Length);

        Assert.AreEqual(33, ReadBigEndianInt(bytes.Slice(0 * scalarSize, scalarSize)));
        Assert.AreEqual(3, ReadBigEndianInt(bytes.Slice(1 * scalarSize, scalarSize)));
        Assert.AreEqual(11, ReadBigEndianInt(bytes.Slice(2 * scalarSize, scalarSize)));
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsWrongFormatLabel()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(
                CircomWitnessFixtures.Multiplier2Bytes,
                WellKnownR1csFormatLabel.CircomBinary);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsWrongMagic()
    {
        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        mutated[0] = (byte)'x';

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(mutated);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsBn254Field()
    {
        //Same prime-mutation pattern as the .r1cs test; the prime sits
        //at offset 12 (file header) + 12 (section header) + 4 (field_size) = 28.
        const int primeOffset = 12 + 12 + 4;
        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        byte[] bn254Be = Convert.FromHexString(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
        for(int i = 0; i < bn254Be.Length; i++)
        {
            mutated[primeOffset + i] = bn254Be[bn254Be.Length - 1 - i];
        }

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(mutated);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsTruncatedFile()
    {
        byte[] full = CircomWitnessFixtures.Multiplier2Bytes;
        byte[] truncated = full.AsSpan(0, full.Length / 2).ToArray();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(truncated);
        });
    }


    [TestMethod]
    public void Multiplier2WitnessRejectsNWitnessAboveAddressableRange()
    {
        //nWitness sits at file header (12) + section header (12) + field_size (4) + prime (32) = 60.
        //A declared nWitness whose (nWitness - 1) * 32-byte dense vector exceeds the maximum array
        //size is rejected at header parse with the reader's documented ArgumentException, not an
        //OverflowException from the allocation. Asserting the guard's OWN message distinguishes it
        //from the section-length mismatch that also rejects this (small) input.
        const int nWitnessOffset = 12 + 12 + 4 + 32;
        const uint hugeNWitness = 100_000_000;   //(nWitness - 1) * 32 ~= 3.2 GB > Array.MaxLength.

        byte[] mutated = (byte[])CircomWitnessFixtures.Multiplier2Bytes.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(nWitnessOffset), hugeNWitness);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csWitness _ = ReadWitnessFixture(mutated);
        });

        Assert.Contains("exceeds the maximum addressable size", exception.Message, "the nWitness range guard must be what rejects the header");
    }


    [TestMethod]
    public void Multiplier2EndToEndProvesAndVerifiesWithStandardSpartan()
    {
        //The capability gate: both files parsed through the adapter,
        //prove with base Spartan, verify with base Spartan, accept.
        const int columnCount = 4;
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);
        using SpartanProver prover = BuildBaseProver(columnCount);
        using SpartanVerifier verifier = BuildBaseVerifier(columnCount);

        using RawR1csInstance proverInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "Base Spartan failed end-to-end on Circom-parsed multiplier2 .r1cs + .wtns.");
    }


    [TestMethod]
    public void Multiplier2EndToEndProvesAndVerifiesWithMaskedSpartan()
    {
        const int hyraxVectorLength = 2;
        using RawR1csWitness witness = ReadWitnessFixture(CircomWitnessFixtures.Multiplier2Bytes);
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength);

        using RawR1csInstance proverInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadR1csFixture(CircomR1csFixtures.Multiplier2Bytes);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "Masked Spartan failed end-to-end on Circom-parsed multiplier2 .r1cs + .wtns.");
    }


    private static RawR1csWitness ReadWitnessFixture(byte[] fixtureBytes) =>
        ReadWitnessFixture(fixtureBytes, WellKnownR1csFormatLabel.CircomWitness);


    private static RawR1csWitness ReadWitnessFixture(byte[] fixtureBytes, WellKnownR1csFormatLabel format)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomWitnessReader.Reader(
            pipe,
            format,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static RawR1csInstance ReadR1csFixture(byte[] fixtureBytes)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static int ReadBigEndianInt(ReadOnlySpan<byte> bytes)
    {
        //The scalar's value is small enough to fit in a 32-bit int —
        //the witness elements are 1, 33, 3, 11. The leading 28 bytes
        //are zeroes; we read only the trailing four-byte big-endian
        //tail.
        ReadOnlySpan<byte> tail = bytes[(bytes.Length - 4)..];
        return BinaryPrimitives.ReadInt32BigEndian(tail);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildBaseProver(int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);

        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            commitmentDims.ColumnCount,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey));

        return new SpartanProver(provingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier via its constructor chain.")]
    private static SpartanVerifier BuildBaseVerifier(int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);

        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            commitmentDims.ColumnCount,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(commitmentKey));

        return new SpartanVerifier(verifyingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver via its constructor chain.")]
    private static MaskedSpartanProver BuildMaskedProver(int hyraxVectorLength)
    {
        //The statistical masks' single-row vector commitments need more
        //generators than the small witness matrix; flooring is byte-neutral
        //(generators derive per index from the seed).
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, Spartan.MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey));

        return new MaskedSpartanProver(provingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanVerifier via its constructor chain.")]
    private static MaskedSpartanVerifier BuildMaskedVerifier(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, Spartan.MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(commitmentKey));

        return new MaskedSpartanVerifier(verifyingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    private static ScalarRandomDelegate ScalarRandom { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }
}