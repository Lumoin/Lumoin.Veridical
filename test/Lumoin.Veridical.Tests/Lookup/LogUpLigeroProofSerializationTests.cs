using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Lookup;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Tests.Lookup;

/// <summary>
/// Gate for the Ligero-shaped LogUp wire codec: a proven argument survives the
/// serialize → reconstruct round trip and still verifies, the reconstructed
/// proof re-serializes to the identical bytes (one canonical wire form), and a
/// wrong-length or tampered wire is rejected. Real BLS12-381 arithmetic and
/// production BLAKE3, matching <see cref="LogUpProofTests"/>.
/// </summary>
[TestClass]
internal sealed class LogUpLigeroProofSerializationTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>
    /// Eight opened columns keep the fixture fast; soundness margins are the
    /// ledger tests' concern, not this codec's.
    /// </summary>
    private const int TestQueryCount = 8;

    /// <summary>Three variables (eight rows) exercise multi-round folding cheaply.</summary>
    private const int TestVariableCount = 3;

    /// <summary>One witness column — the shape the CLI's memberOf lookup uses.</summary>
    private const int TestWitnessColumnCount = 1;

    /// <summary>The Ligero inverse code rate the fixture commits under.</summary>
    private const int TestInverseRate = WellKnownLigeroParameters.DefaultInverseRate;

    /// <summary>The Fiat-Shamir domain label of the fixture's transcripts.</summary>
    private const string TranscriptDomain = "veridical.logup.serialization.test.v1";

    /// <summary>A fill salt matching no other stream in the suite, keeping the table reproducible and distinct.</summary>
    private const int TableFillSalt = 8311;

    /// <summary>A stride coprime to the cube, so every witness row lands on a distinct table position.</summary>
    private const int WitnessRowStride = 5;

    /// <summary>A second stride distinct from <see cref="WitnessRowStride"/>, giving a second witness column its own row-to-table mapping.</summary>
    private const int SecondWitnessRowStride = 3;

    /// <summary>Two witness columns exercise the wire layout beyond the CLI's single-column shape without leaving the fixture's fast three-variable cube.</summary>
    private const int MultiWitnessColumnCount = 2;

    /// <summary>The smallest variable count a dimension-cap pin needs; the pin is about the size arithmetic, not a real argument shape.</summary>
    private const int MinimalVariableCount = 1;

    /// <summary>The smallest witness-column count a dimension-cap pin needs.</summary>
    private const int MinimalWitnessColumnCount = 1;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void WireRoundTripVerifiesAndReserializesIdentically()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(pool);
        using LogUpProof proof = Prove(material, pcs, pool);

        int wireSize = LogUpLigeroProofSerialization.GetBufferSizeBytes(TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        using IMemoryOwner<byte> wireOwner = pool.Rent(wireSize);
        Span<byte> wire = wireOwner.Memory.Span[..wireSize];
        LogUpLigeroProofSerialization.Write(proof, TestQueryCount, TestInverseRate, DigestSizeBytes, wire);

        using LogUpProof reconstructed = LogUpLigeroProofSerialization.FromBytes(wire, TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve, pool);

        Assert.IsTrue(Verify(material, reconstructed, pcs, pool), "A wire-round-tripped LogUp proof must still verify.");

        using IMemoryOwner<byte> secondOwner = pool.Rent(wireSize);
        Span<byte> second = secondOwner.Memory.Span[..wireSize];
        LogUpLigeroProofSerialization.Write(reconstructed, TestQueryCount, TestInverseRate, DigestSizeBytes, second);

        Assert.IsTrue(wire.SequenceEqual(second), "Re-serializing the reconstructed proof must reproduce the identical wire bytes.");
    }


    [TestMethod]
    public void WrongWireLengthIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int wireSize = LogUpLigeroProofSerialization.GetBufferSizeBytes(TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        using IMemoryOwner<byte> shortOwner = pool.Rent(wireSize - 1);

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using LogUpProof _ = LogUpLigeroProofSerialization.FromBytes(
                shortOwner.Memory.Span[..(wireSize - 1)], TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve, pool);
        });
    }


    [TestMethod]
    public void TamperedWireIsRejectedByTheVerifier()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(pool);
        using LogUpProof proof = Prove(material, pcs, pool);

        int wireSize = LogUpLigeroProofSerialization.GetBufferSizeBytes(TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        using IMemoryOwner<byte> wireOwner = pool.Rent(wireSize);
        Span<byte> wire = wireOwner.Memory.Span[..wireSize];
        LogUpLigeroProofSerialization.Write(proof, TestQueryCount, TestInverseRate, DigestSizeBytes, wire);

        //The final byte sits inside the helper opening — a component whose
        //integrity only the verifier's opening check enforces.
        wire[^1] ^= 0x01;

        using LogUpProof tampered = LogUpLigeroProofSerialization.FromBytes(wire, TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve, pool);

        Assert.IsFalse(Verify(material, tampered, pcs, pool), "A tampered helper opening must fail verification.");
    }


    /// <summary>A wire buffer one byte longer than the layout's exact size is rejected, mirroring the shorter-buffer rejection <see cref="WrongWireLengthIsRejected"/> pins.</summary>
    [TestMethod]
    public void WireOneByteLongerThanExpectedIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int wireSize = LogUpLigeroProofSerialization.GetBufferSizeBytes(TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        using IMemoryOwner<byte> longOwner = pool.Rent(wireSize + 1);

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using LogUpProof _ = LogUpLigeroProofSerialization.FromBytes(
                longOwner.Memory.Span[..(wireSize + 1)], TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve, pool);
        });
    }


    /// <summary>A proof spanning more than one witness column survives the wire round trip, verifies, and re-serializes to the identical bytes — the layout's per-column repetition is exercised, not just its single-column shape.</summary>
    [TestMethod]
    public void MultiWitnessColumnProofRoundTripsByteIdentically()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(pool, MultiWitnessColumnCount);
        using LogUpProof proof = Prove(material, pcs, pool, MultiWitnessColumnCount);

        int wireSize = LogUpLigeroProofSerialization.GetBufferSizeBytes(TestVariableCount, MultiWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        using IMemoryOwner<byte> wireOwner = pool.Rent(wireSize);
        Span<byte> wire = wireOwner.Memory.Span[..wireSize];
        LogUpLigeroProofSerialization.Write(proof, TestQueryCount, TestInverseRate, DigestSizeBytes, wire);

        using LogUpProof reconstructed = LogUpLigeroProofSerialization.FromBytes(wire, TestVariableCount, MultiWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve, pool);

        Assert.IsTrue(Verify(material, reconstructed, pcs, pool), "A wire-round-tripped multi-witness-column proof must still verify.");

        using IMemoryOwner<byte> secondOwner = pool.Rent(wireSize);
        Span<byte> second = secondOwner.Memory.Span[..wireSize];
        LogUpLigeroProofSerialization.Write(reconstructed, TestQueryCount, TestInverseRate, DigestSizeBytes, second);

        Assert.IsTrue(wire.SequenceEqual(second), "Re-serializing the reconstructed multi-column proof must reproduce the identical wire bytes.");
    }


    /// <summary>
    /// A one-byte flip inside any one of the eight layout sections — the witness
    /// commitment, the multiplicity commitment, the helper commitment, the round
    /// messages, the claimed evaluations, the witness opening, the multiplicity
    /// opening, or the helper opening — is caught: either the canonicity funnel in
    /// <see cref="LogUpLigeroProofSerialization.FromBytes"/> throws, or the
    /// reconstructed proof fails verification. No section's integrity depends on a
    /// sibling section catching the tamper for it.
    /// </summary>
    [TestMethod]
    public void TamperingEachLayoutSectionIsCaught()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(pool);
        using LogUpProof proof = Prove(material, pcs, pool);

        int wireSize = LogUpLigeroProofSerialization.GetBufferSizeBytes(TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        using IMemoryOwner<byte> referenceOwner = pool.Rent(wireSize);
        Span<byte> reference = referenceOwner.Memory.Span[..wireSize];
        LogUpLigeroProofSerialization.Write(proof, TestQueryCount, TestInverseRate, DigestSizeBytes, reference);

        int roundSectionBytes = TestVariableCount * LogUpSumcheck.RoundEvaluationCount(TestWitnessColumnCount) * ScalarSize;
        int claimedSectionBytes = (TestWitnessColumnCount + LogUpSumcheck.AuxiliaryColumnCount) * ScalarSize;
        int openingSectionBytes = LigeroPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(TestVariableCount, Curve, TestQueryCount, DigestSizeBytes, TestInverseRate);

        int witnessCommitmentOffset = 0;
        int multiplicityCommitmentOffset = witnessCommitmentOffset + (TestWitnessColumnCount * DigestSizeBytes);
        int helperCommitmentOffset = multiplicityCommitmentOffset + DigestSizeBytes;
        int roundMessagesOffset = helperCommitmentOffset + DigestSizeBytes;
        int claimedEvaluationsOffset = roundMessagesOffset + roundSectionBytes;
        int witnessOpeningOffset = claimedEvaluationsOffset + claimedSectionBytes;
        int multiplicityOpeningOffset = witnessOpeningOffset + (TestWitnessColumnCount * openingSectionBytes);
        int helperOpeningOffset = multiplicityOpeningOffset + openingSectionBytes;

        int[] sectionOffsets =
        [
            witnessCommitmentOffset,
            multiplicityCommitmentOffset,
            helperCommitmentOffset,
            roundMessagesOffset,
            claimedEvaluationsOffset,
            witnessOpeningOffset,
            multiplicityOpeningOffset,
            helperOpeningOffset,
        ];

        foreach(int sectionOffset in sectionOffsets)
        {
            using IMemoryOwner<byte> tamperedOwner = pool.Rent(wireSize);
            Span<byte> tampered = tamperedOwner.Memory.Span[..wireSize];
            reference.CopyTo(tampered);
            tampered[sectionOffset] ^= 0x01;

            LogUpProof? reconstructed = null;
            bool rejectedAtParse = false;
            try
            {
                reconstructed = LogUpLigeroProofSerialization.FromBytes(tampered, TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve, pool);
            }
            catch(ArgumentException)
            {
                rejectedAtParse = true;
            }

            if(!rejectedAtParse)
            {
                using(reconstructed)
                {
                    Assert.IsFalse(Verify(material, reconstructed!, pcs, pool), $"A tampered byte at section offset {sectionOffset} must be caught by parsing or verification.");
                }
            }
        }
    }


    /// <summary>Writing into a destination whose length does not match the proof's dimensions throws instead of writing a truncated or overrun buffer.</summary>
    [TestMethod]
    public void WriteToWrongLengthDestinationThrows()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(pool);
        using LogUpProof proof = Prove(material, pcs, pool);

        int wireSize = LogUpLigeroProofSerialization.GetBufferSizeBytes(TestVariableCount, TestWitnessColumnCount, TestQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        using IMemoryOwner<byte> destinationOwner = pool.Rent(wireSize);

        Assert.ThrowsExactly<ArgumentException>(() => WriteAtWrongLength(proof, destinationOwner, wireSize - 1));
    }


    /// <summary>Calls <see cref="LogUpLigeroProofSerialization.Write"/> against a destination of <paramref name="destinationLength"/> bytes; a plain method (not a lambda body) so the destination span never needs to cross a closure boundary.</summary>
    private static void WriteAtWrongLength(LogUpProof proof, IMemoryOwner<byte> destinationOwner, int destinationLength)
    {
        Span<byte> destination = destinationOwner.Memory.Span[..destinationLength];
        LogUpLigeroProofSerialization.Write(proof, TestQueryCount, TestInverseRate, DigestSizeBytes, destination);
    }


    /// <summary>The opened-column query count is accepted at its wired cap and rejected one past it, with the out-of-range exception naming the query-count parameter.</summary>
    [TestMethod]
    public void QueryCountCapBoundaryIsEnforced()
    {
        int atCap = LogUpLigeroProofSerialization.GetBufferSizeBytes(MinimalVariableCount, MinimalWitnessColumnCount, LogUpLigeroProofSerialization.MaximumQueryCount, TestInverseRate, DigestSizeBytes, Curve);
        Assert.IsGreaterThan(0, atCap);

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            LogUpLigeroProofSerialization.GetBufferSizeBytes(MinimalVariableCount, MinimalWitnessColumnCount, LogUpLigeroProofSerialization.MaximumQueryCount + 1, TestInverseRate, DigestSizeBytes, Curve));
        Assert.AreEqual("queryCount", exception.ParamName);
    }


    /// <summary>The inverse code rate is accepted at its wired cap and rejected one past it, with the out-of-range exception naming the inverse-rate parameter.</summary>
    [TestMethod]
    public void InverseRateCapBoundaryIsEnforced()
    {
        int atCap = LogUpLigeroProofSerialization.GetBufferSizeBytes(MinimalVariableCount, MinimalWitnessColumnCount, TestQueryCount, LogUpLigeroProofSerialization.MaximumInverseRate, DigestSizeBytes, Curve);
        Assert.IsGreaterThan(0, atCap);

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            LogUpLigeroProofSerialization.GetBufferSizeBytes(MinimalVariableCount, MinimalWitnessColumnCount, TestQueryCount, LogUpLigeroProofSerialization.MaximumInverseRate + 1, DigestSizeBytes, Curve));
        Assert.AreEqual("inverseRate", exception.ParamName);
    }


    /// <summary>The Merkle digest size is accepted at its wired cap and rejected one past it, with the out-of-range exception naming the digest-size parameter.</summary>
    [TestMethod]
    public void DigestSizeBytesCapBoundaryIsEnforced()
    {
        int atCap = LogUpLigeroProofSerialization.GetBufferSizeBytes(MinimalVariableCount, MinimalWitnessColumnCount, TestQueryCount, TestInverseRate, LogUpLigeroProofSerialization.MaximumDigestSizeBytes, Curve);
        Assert.IsGreaterThan(0, atCap);

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            LogUpLigeroProofSerialization.GetBufferSizeBytes(MinimalVariableCount, MinimalWitnessColumnCount, TestQueryCount, TestInverseRate, LogUpLigeroProofSerialization.MaximumDigestSizeBytes + 1, Curve));
        Assert.AreEqual("digestSizeBytes", exception.ParamName);
    }


    /// <summary>Dimensions that each individually pass their own cap can still jointly describe a proof longer than <see cref="int.MaxValue"/> bytes, which is rejected as an argument error rather than silently wrapping the computed size.</summary>
    [TestMethod]
    public void JointDimensionOverflowIsRejected()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            LogUpLigeroProofSerialization.GetBufferSizeBytes(
                LogUpProver.MaximumVariableCount,
                LogUpProver.MaximumWitnessColumnCount,
                LogUpLigeroProofSerialization.MaximumQueryCount,
                TestInverseRate,
                LogUpLigeroProofSerialization.MaximumDigestSizeBytes,
                Curve));
    }


    private static LogUpProof Prove(IMemoryOwner<byte> material, PolynomialCommitmentProvider pcs, BaseMemoryPool pool, int witnessColumnCount = TestWitnessColumnCount)
    {
        int size = 1 << TestVariableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        ReadOnlySpan<byte> witness = material.Memory.Span.Slice(size * ScalarSize, witnessColumnCount * size * ScalarSize);
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpProver.Prove(
            table, witness, TestVariableCount, witnessColumnCount, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);
    }


    private static bool Verify(IMemoryOwner<byte> material, LogUpProof proof, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << proof.VariableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpVerifier.Verify(
            table, proof, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MleEvaluate, pool);
    }


    private static IMemoryOwner<byte> BuildLookupMaterial(BaseMemoryPool pool, int witnessColumnCount = TestWitnessColumnCount)
    {
        int size = 1 << TestVariableCount;
        int totalBytes = (1 + witnessColumnCount) * size * ScalarSize;
        IMemoryOwner<byte> owner = pool.Rent(totalBytes);
        Span<byte> material = owner.Memory.Span[..totalBytes];
        Span<byte> table = material[..(size * ScalarSize)];
        DeterministicScalarFill.FillCanonical(table, TableFillSalt, Reduce, Curve);

        for(int column = 0; column < witnessColumnCount; column++)
        {
            Span<byte> witness = material.Slice((1 + column) * size * ScalarSize, size * ScalarSize);
            int stride = column == 0 ? WitnessRowStride : SecondWitnessRowStride;
            for(int row = 0; row < size; row++)
            {
                int tableIndex = row * stride % size;
                table.Slice(tableIndex * ScalarSize, ScalarSize).CopyTo(witness.Slice(row * ScalarSize, ScalarSize));
            }
        }

        return owner;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key material; callers dispose the provider itself.")]
    private static PolynomialCommitmentProvider BuildLigeroProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce,
            Hash, Squeeze, Hash, HashTwoToOne, WellKnownHashAlgorithms.Blake3, DigestSizeBytes, TestInverseRate);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
