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
/// Conformance tests for the Circom <c>.r1cs</c> reader: structural
/// parse, error-path validation, and end-to-end prove-and-verify
/// against both the base and masked Spartan provers on the parsed
/// instance.
/// </summary>
[TestClass]
internal sealed class CircomR1csReaderTests
{
    [TestMethod]
    public void Multiplier2R1csParsesIntoExpectedShape()
    {
        using RawR1csInstance instance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);

        //Multiplier2 (padded): 2 constraints, 4 variables, no public
        //inputs in the Veridical sense (all wires routed into the
        //witness — see CircomR1csReader's remarks on the public-input
        //convention).
        Assert.AreEqual(2, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(2, instance.B.RowCount, "B.RowCount");
        Assert.AreEqual(2, instance.C.RowCount, "C.RowCount");

        Assert.AreEqual(4, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(4, instance.B.ColumnCount, "B.ColumnCount");
        Assert.AreEqual(4, instance.C.ColumnCount, "C.ColumnCount");

        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount");

        //Each matrix has exactly 2 non-zeros: one per constraint row.
        Assert.AreEqual(2, instance.A.NonzeroCount, "A.NonzeroCount");
        Assert.AreEqual(2, instance.B.NonzeroCount, "B.NonzeroCount");
        Assert.AreEqual(2, instance.C.NonzeroCount, "C.NonzeroCount");

        //Triples — C0: a*b=c, C1: 1*1=1 padding.
        (int aRow0, int aCol0) = instance.A.GetTriplePosition(0);
        (int aRow1, int aCol1) = instance.A.GetTriplePosition(1);
        Assert.AreEqual((0, 2), (aRow0, aCol0), "A[0] expected at constraint 0, wire 2 (a)");
        Assert.AreEqual((1, 0), (aRow1, aCol1), "A[1] expected at padding constraint, constant wire");

        (int bRow0, int bCol0) = instance.B.GetTriplePosition(0);
        (int cRow0, int cCol0) = instance.C.GetTriplePosition(0);
        Assert.AreEqual((0, 3), (bRow0, bCol0), "B[0] expected at constraint 0, wire 3 (b)");
        Assert.AreEqual((0, 1), (cRow0, cCol0), "C[0] expected at constraint 0, wire 1 (c)");
    }


    //The .r1cs header section stores nWires as a little-endian uint32 at byte offset 60
    //(12 file header + 12 section header + 4 field_size + 32 prime) and nConstraints at
    //offset 84. Both are attacker-controlled; a value above int.MaxValue must be rejected
    //as malformed rather than overflow the checked (int) cast during construction. Offsets
    //are the ones a fuzz sweep of this committed fixture triggered the overflow through.
    private const int NWiresLittleEndianOffset = 60;
    private const int NConstraintsLittleEndianOffset = 84;


    [TestMethod]
    [DataRow(NWiresLittleEndianOffset)]
    [DataRow(NConstraintsLittleEndianOffset)]
    public void R1csRejectsHeaderCountAboveInt32Range(int littleEndianOffset)
    {
        //Sanity: the untampered fixture parses, so the single tamper below is the only
        //change under test (and a fixture drift that moved the field would fail loudly here).
        using(RawR1csInstance _ = ReadFixture(CircomR1csFixtures.Multiplier2Bytes))
        {
        }

        byte[] tampered = CircomR1csFixtures.Multiplier2Bytes;
        BinaryPrimitives.WriteUInt32LittleEndian(tampered.AsSpan(littleEndianOffset, sizeof(uint)), uint.MaxValue);

        //Before the upper-bound guard this surfaced as an OverflowException from the
        //checked (int) cast; ThrowsExactly<ArgumentException> pins the documented rejection.
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(tampered);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsWrongFormatLabel()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(
                CircomR1csFixtures.Multiplier2Bytes,
                WellKnownR1csFormatLabel.CircomWitness);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsWrongMagic()
    {
        byte[] mutated = (byte[])CircomR1csFixtures.Multiplier2Bytes.Clone();
        mutated[0] = (byte)'x'; //corrupt the 'r' of "r1cs"

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(mutated);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsBn254Field()
    {
        //Construct a header with BN254's scalar prime in place of
        //BLS12-381's. BN254 r =
        //  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        byte[] bn254FieldFixture = MutatePrimeBytes(
            CircomR1csFixtures.Multiplier2Bytes,
            replacementPrimeBigEndianHex:
                "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(bn254FieldFixture);
        });
    }


    [TestMethod]
    public void Multiplier2R1csRejectsTruncatedFile()
    {
        //Cut the fixture in half — guaranteed to land mid-section.
        byte[] full = CircomR1csFixtures.Multiplier2Bytes;
        byte[] truncated = full.AsSpan(0, full.Length / 2).ToArray();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = ReadFixture(truncated);
        });
    }


    [TestMethod]
    public void Multiplier2R1csParsedInstanceProvesAndVerifiesWithStandardSpartan()
    {
        //Build proving + verifying keys against the parsed instance,
        //feed a satisfying witness (a=3, b=11, c=33), prove with the
        //base Spartan prover, verify with the base Spartan verifier.
        const int rowCount = 2;
        const int columnCount = 4;

        using RawR1csWitness witness = BuildMultiplier2Witness();

        using SpartanProver prover = BuildBaseProver(rowCount, columnCount);
        using SpartanVerifier verifier = BuildBaseVerifier(rowCount, columnCount);

        using RawR1csInstance proverInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);

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

        Assert.IsTrue(verified, "Base Spartan failed to verify a Circom-parsed multiplier2 instance.");
    }


    [TestMethod]
    public void Multiplier2R1csParsedInstanceProvesAndVerifiesWithMaskedSpartan()
    {
        const int hyraxVectorLength = 2;

        using RawR1csWitness witness = BuildMultiplier2Witness();

        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength);

        using RawR1csInstance proverInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);
        using RawR1csInstance verifierInstance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes);

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

        Assert.IsTrue(verified, "Masked Spartan failed to verify a Circom-parsed multiplier2 instance.");
    }


    private static RawR1csInstance ReadFixture(byte[] fixtureBytes) =>
        ReadFixture(fixtureBytes, WellKnownR1csFormatLabel.CircomBinary);


    private static RawR1csInstance ReadFixture(byte[] fixtureBytes, WellKnownR1csFormatLabel format)
    {
        var stream = new MemoryStream(fixtureBytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return CircomR1csReader.Reader(
            pipe,
            format,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    /// <summary>
    /// Returns a copy of <paramref name="fixtureBytes"/> with the
    /// header section's prime modulus (32 little-endian bytes at offset
    /// <c>20</c>: 12 file header + 12 section header + 4 field_size)
    /// replaced by the bytes of <paramref name="replacementPrimeBigEndianHex"/>
    /// (reversed to little-endian on the way in).
    /// </summary>
    private static byte[] MutatePrimeBytes(byte[] fixtureBytes, string replacementPrimeBigEndianHex)
    {
        const int primeOffset = 12 + 12 + 4;
        byte[] mutated = (byte[])fixtureBytes.Clone();
        byte[] replacementBe = Convert.FromHexString(replacementPrimeBigEndianHex);
        //File stores prime little-endian; reverse on the way in.
        for(int i = 0; i < replacementBe.Length; i++)
        {
            mutated[primeOffset + i] = replacementBe[replacementBe.Length - 1 - i];
        }

        return mutated;
    }


    private static RawR1csWitness BuildMultiplier2Witness()
    {
        //z = (1, c, a, b) = (1, 33, 3, 11) — satisfies a * b = c with
        //a = 3, b = 11. PublicInputCount = 0 means z[1..] is the
        //entire witness, in Veridical order matching Circom's wire
        //ordering.
        int scalarSize = WellKnownCurves.Bls12Curve381ScalarSizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(33), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(11), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildBaseProver(int rowCount, int columnCount)
    {
        using(RawR1csInstance instance = ReadFixture(CircomR1csFixtures.Multiplier2Bytes))
        {
            Assert.AreEqual(rowCount, instance.A.RowCount);
            Assert.AreEqual(columnCount, instance.A.ColumnCount);
        }

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
    private static SpartanVerifier BuildBaseVerifier(int rowCount, int columnCount)
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


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}