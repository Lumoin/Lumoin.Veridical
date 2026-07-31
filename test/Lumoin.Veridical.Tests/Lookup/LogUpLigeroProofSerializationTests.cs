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


    private static LogUpProof Prove(IMemoryOwner<byte> material, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << TestVariableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        ReadOnlySpan<byte> witness = material.Memory.Span.Slice(size * ScalarSize, TestWitnessColumnCount * size * ScalarSize);
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpProver.Prove(
            table, witness, TestVariableCount, TestWitnessColumnCount, pcs, transcript,
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


    private static IMemoryOwner<byte> BuildLookupMaterial(BaseMemoryPool pool)
    {
        int size = 1 << TestVariableCount;
        IMemoryOwner<byte> owner = pool.Rent((1 + TestWitnessColumnCount) * size * ScalarSize);
        Span<byte> material = owner.Memory.Span[..((1 + TestWitnessColumnCount) * size * ScalarSize)];
        Span<byte> table = material[..(size * ScalarSize)];
        DeterministicScalarFill.FillCanonical(table, TableFillSalt, Reduce, Curve);

        Span<byte> witness = material.Slice(size * ScalarSize, size * ScalarSize);
        for(int row = 0; row < size; row++)
        {
            int tableIndex = row * WitnessRowStride % size;
            table.Slice(tableIndex * ScalarSize, ScalarSize).CopyTo(witness.Slice(row * ScalarSize, ScalarSize));
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
