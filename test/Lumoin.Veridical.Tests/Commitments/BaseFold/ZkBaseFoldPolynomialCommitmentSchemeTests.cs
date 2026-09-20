using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Diagnostics.Metrics;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for <see cref="ZkBaseFoldPolynomialCommitmentScheme"/>: the
/// hiding BaseFold scheme behind the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface. These drive
/// commit → open → verify end to end through the salted-Merkle leaf commitment,
/// exercising the per-query leaf salts the hiding opening carries, and assert
/// the hiding property the non-hiding sibling lacks: committing the same
/// polynomial twice yields different roots. Real BLS12-381 arithmetic and
/// production BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class ZkBaseFoldPolynomialCommitmentSchemeTests
{
    /// <summary>The BLS12-381 scalar addition backend.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar reduction backend.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 hash-to-scalar backend.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The entropy-sourced scalar sampler behind every mask and salt.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

    /// <summary>The independent big-integer MLE evaluation reference.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>The wired Merkle digest size: BLAKE3's 32 bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The wire size of one compressed sumcheck round polynomial, two scalars.</summary>
    private const int RoundPolynomialBytes = 2 * ScalarSize;

    /// <summary>The query count every provider in this suite is built with.</summary>
    private const int TestQueryCount = 12;

    /// <summary>
    /// The widest digest the Merkle surface admits — twice the scalar width,
    /// so the scheme's leaf commitment genuinely runs on every layer instead
    /// of taking the verbatim scalar-wide path.
    /// </summary>
    private const int WideDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;

    /// <summary>
    /// Two layers, so the opening carries a fold root and authentication
    /// paths — the sections a wide digest prices wider.
    /// </summary>
    private const int WideDigestVariableCount = 2;

    /// <summary>The curve every artifact is tagged with.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Every zero-knowledge provider factory accepts an empty seed without renting storage.</summary>
    [TestMethod]
    public void EmptySeedsRentNothing()
    {
        using var meter = new Meter(nameof(EmptySeedsRentNothing));
        using var listener = new MeterListener();
        long rents = 0;
        listener.InstrumentPublished = (instrument, observer) =>
        {
            if(ReferenceEquals(instrument.Meter, meter))
            {
                observer.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if(instrument.Name == BaseMemoryPoolMetrics.BaseMemoryPoolRentOperationsTotal)
            {
                rents += measurement;
            }
        });
        listener.Start();
        using BaseMemoryPool pool = new(meter);

        //One extra variable is the smallest accepted lift at factory creation.
        const int ExtraMaskVariableCount = 1;
        using(PolynomialCommitmentProvider salted = ZkBaseFoldPolynomialCommitmentScheme.Create(
            ReadOnlySpan<byte>.Empty, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce,
            Add, Subtract, Multiply, Invert, Random, HashToScalar, pool))
        using(PolynomialCommitmentProvider lifted = ZkBaseFoldPolynomialCommitmentScheme.CreateZeroKnowledge(
            ReadOnlySpan<byte>.Empty, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce,
            Add, Subtract, Multiply, Invert, Random, HashToScalar, ExtraMaskVariableCount, pool))
        using(PolynomialCommitmentProvider full = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            ReadOnlySpan<byte>.Empty, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce,
            Add, Subtract, Multiply, Invert, Random, HashToScalar, ExtraMaskVariableCount, pool))
        {
            Assert.AreEqual(0L, rents);
        }

        Assert.AreEqual(0L, rents);
    }


    /// <summary>Checks that committing, opening and verifying succeeds for the selected variable count.</summary>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void CommitOpenVerifyRoundTrips(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(pool);

        Assert.IsTrue(provider.IsHiding, "The ZK BaseFold provider must report itself as hiding.");

        using MultilinearExtension mle = BuildRandomMle(variableCount, 1, pool);
        Scalar[] point = BuildPoint(variableCount, 5, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                Assert.AreEqual(CommitmentScheme.BaseFold, commitment.Scheme, "Commitment must be stamped BaseFold.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using Scalar expected = mle.Evaluate(point, MleEvaluate, pool);
                    Assert.IsTrue(
                        claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                        $"Opened claimed value must equal f(z) for n = {variableCount}.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsTrue(verified, $"An honest hiding commit→open→verify must round-trip for n = {variableCount}.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// The digest width is a real capability for the hiding flavour too: the
    /// salted leaves are committed to the configured node width, the
    /// randomized commitment root carries it, the opening fills exactly the
    /// wide-digest budget, and verification recomputes the salted leaf at the
    /// root's width.
    /// </summary>
    [TestMethod]
    public void CommitOpenVerifyRoundTripsAtAWideDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(pool, WideDigestSizeBytes);

        using MultilinearExtension mle = BuildRandomMle(WideDigestVariableCount, 1, pool);
        Scalar[] point = BuildPoint(WideDigestVariableCount, 5, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                Assert.HasCount(WideDigestSizeBytes, commitment.AsReadOnlySpan(), "The hiding commitment is one Merkle root at the configured node width.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    int expectedOpeningBytes = ZkBaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
                        WideDigestVariableCount, Curve, TestQueryCount, WideDigestSizeBytes);
                    Assert.HasCount(expectedOpeningBytes, opening.AsReadOnlySpan(), "The hiding opening must fill exactly the wide-digest budget.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsTrue(
                        provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        "An honest hiding commit→open→verify must round-trip at the wide digest.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Checks that committing the same polynomial twice yields different roots.</summary>
    [TestMethod]
    public void CommittingTheSamePolynomialTwiceYieldsDifferentRoots()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider(pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 9, pool);

        (PolynomialCommitment first, PolynomialCommitmentBlind firstBlind) = provider.Commit(mle, pool);
        (PolynomialCommitment second, PolynomialCommitmentBlind secondBlind) = provider.Commit(mle, pool);

        using(first)
        using(firstBlind)
        using(second)
        using(secondBlind)
        {
            //The salted leaves randomise the root: the same witness commits to
            //different bytes, so the commitment is not a deterministic fingerprint of the witness.
            Assert.IsFalse(
                first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
                "A hiding commitment must not be a deterministic function of the witness.");
        }
    }


    /// <summary>Checks that tampered opening is rejected.</summary>
    [TestMethod]
    public void TamperedOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider(pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 2, pool);
        Scalar[] point = BuildPoint(VariableCount, 6, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    //Flip a byte inside the opening (a round-polynomial coefficient).
                    MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[0] ^= 0x01;

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A tampered opening must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Checks that tampered leaf salt is rejected.</summary>
    [TestMethod]
    public void TamperedLeafSaltIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider(pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 10, pool);
        Scalar[] point = BuildPoint(VariableCount, 11, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    //Flip a byte inside the first revealed leaf salt: the verifier
                    //recomputes hash(value ‖ salt) for the leaf, so a corrupted salt
                    //must fail the authentication path against the layer root.
                    MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[FirstLeafSaltOffset(VariableCount)] ^= 0x01;

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A tampered leaf salt must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Checks that tampered commitment is rejected.</summary>
    [TestMethod]
    public void TamperedCommitmentIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider(pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 3, pool);
        Scalar[] point = BuildPoint(VariableCount, 7, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using PolynomialCommitment tampered = TamperFirstByte(commitment, pool);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(tampered, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A tampered commitment must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Checks that wrong claimed value is rejected.</summary>
    [TestMethod]
    public void WrongClaimedValueIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider(pool);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 4, pool);
        Scalar[] point = BuildPoint(VariableCount, 8, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using Scalar wrong = AddOne(claimedValue, pool);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, wrong, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A wrong claimed value must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>The byte offset of the first revealed leaf salt in a hiding opening: it sits right after the d round polynomials, the d−1 fold roots, the cleartext base codeword, and the first query's first step's two pair values.</summary>
    private static int FirstLeafSaltOffset(int variableCount)
    {
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(variableCount, Curve);
        int baseUnit = parameters.InverseRate * parameters.BaseDimension;

        int header = (variableCount * RoundPolynomialBytes)
            + ((variableCount - 1) * DigestSizeBytes)
            + (baseUnit * ScalarSize);

        return header + (2 * ScalarSize);
    }


    /// <summary>One byte past the widest digest the path verifier reserves stack space for, which is where a configuration stops being serviceable at all.</summary>
    private const int TooWideDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes + 1;


    /// <summary>
    /// Bounds the configured digest width where the provider is wired. The
    /// authentication-path verifier recomputes a node into a stack buffer
    /// reserved at <see cref="WellKnownMerkleHashParameters.MaximumDigestSizeBytes"/>,
    /// so a wider digest has nowhere to land, and the failure would otherwise
    /// surface as a slice fault raised from inside a verification, far from the
    /// wiring that caused it. Refusing it at construction names the mistake
    /// where it was made, and leaves the widest supported digest legal.
    /// </summary>
    [TestMethod]
    public void CreateRefusesADigestWiderThanTheVerifierReservesFor()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => ZkBaseFoldPolynomialCommitmentScheme.Create(
                Seed,
                Curve,
                TestQueryCount,
                Merkle,
                Hash,
                Squeeze,
                Reduce,
                Add,
                Subtract,
                Multiply,
                Invert,
                Random,
                HashToScalar, BaseMemoryPool.Shared,
                digestSizeBytes: TooWideDigestSizeBytes).Dispose(),
            "A digest wider than the verifier's reserved stack space must be refused where the provider is wired.");
    }


    /// <summary>Builds a provider at the default digest width using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool)
    {
        return NewProvider(pool, DigestSizeBytes);
    }


    /// <summary>
    /// The hiding provider at the test figures and an explicit digest size.
    /// </summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="digestSizeBytes">The Merkle digest width in bytes.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool, int digestSizeBytes)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.Create(
            Seed,
            Curve,
            TestQueryCount,
            Merkle,
            Hash,
            Squeeze,
            Reduce,
            Add,
            Subtract,
            Multiply,
            Invert,
            Random,
            HashToScalar, pool,
            digestSizeBytes: digestSizeBytes);
    }


    /// <summary>Rebuilds the commitment with its first byte flipped.</summary>
    private static PolynomialCommitment TamperFirstByte(PolynomialCommitment commitment, BaseMemoryPool pool)
    {
        Span<byte> bytes = stackalloc byte[commitment.AsReadOnlySpan().Length];
        commitment.AsReadOnlySpan().CopyTo(bytes);
        bytes[0] ^= 0x01;

        return PolynomialCommitment.FromBytes(bytes, Curve, CommitmentScheme.BaseFold, pool);
    }


    /// <summary>A deterministic dense MLE over the boolean cube.</summary>
    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 137) + (i * 19) + 1);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 11) + (i * 31) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);
    }


    /// <summary>A deterministic evaluation point, one scalar per variable.</summary>
    private static Scalar[] BuildPoint(int variableCount, int salt, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 59) + (i * 23) + 2);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 29) + (i * 43) + 5);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            point[i] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return point;
    }


    /// <summary>Adds one to a scalar, returning a fresh pool-owned result.</summary>
    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>Disposes every coordinate of an evaluation point.</summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>A fresh transcript under the BaseFold domain label with empty context.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>The two-to-one compression: BLAKE3 over the concatenated children.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        //Buffered for the widest node the Merkle surface admits and sliced to
        //the actual input widths, so the same compression serves the default
        //and the wide-digest providers; BLAKE3 writes exactly output.Length.
        Span<byte> combined = stackalloc byte[2 * WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The fixed domain-separated seed every provider in this suite is derived from.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.Provider.Test"u8;
}
