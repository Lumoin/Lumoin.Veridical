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
/// Tests for <see cref="BaseFoldPolynomialCommitmentScheme"/>: the
/// BaseFold scheme behind the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface Spartan operates against.
/// These drive commit → open → verify end to end through the broad
/// <see cref="PolynomialCommitment"/> / <see cref="PolynomialOpening"/> /
/// <see cref="PolynomialCommitmentBlind"/> leaf types — exercising the proof
/// byte (de)serialization the rich-type evaluation tests bypass. Real
/// BLS12-381 arithmetic and production BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class BaseFoldPolynomialCommitmentSchemeTests
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


    /// <summary>An empty retained seed needs no rental during provider creation or disposal.</summary>
    [TestMethod]
    public void EmptySeedRentsNothing()
    {
        using var meter = new Meter(nameof(EmptySeedRentsNothing));
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

        using(PolynomialCommitmentProvider provider = BaseFoldPolynomialCommitmentScheme.Create(
            ReadOnlySpan<byte>.Empty, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce,
            Add, Subtract, Multiply, Invert, HashToScalar, pool))
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

                    Assert.IsTrue(verified, $"An honest commit→open→verify must round-trip for n = {variableCount}.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
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


    /// <summary>
    /// The digest width is a real capability, not a label: at a node width
    /// other than the scalar width the scheme leaf-commits every codeword
    /// value, the commitment root and every fold root carry the configured
    /// width, the opening fills exactly the budget the length arithmetic
    /// prices, and verification recomputes the same leaf commitment. Both of
    /// the provider's sizing seams must state the widths the artifacts
    /// actually have.
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
                Assert.HasCount(WideDigestSizeBytes, commitment.AsReadOnlySpan(), "The commitment is one Merkle root at the configured node width.");

                PolynomialCommitmentSizeDelegate? commitmentSeam = provider.CommitmentSizeBytes;
                Assert.IsNotNull(commitmentSeam, "A hash-tree provider must state its commitment width.");
                Assert.AreEqual(WideDigestSizeBytes, commitmentSeam(WideDigestVariableCount), "The commitment seam must state the width Commit produces.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    int expectedOpeningBytes = BaseFoldPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(
                        WideDigestVariableCount, Curve, TestQueryCount, WideDigestSizeBytes);
                    Assert.HasCount(expectedOpeningBytes, opening.AsReadOnlySpan(), "The opening must fill exactly the wide-digest budget.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsTrue(
                        provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        "An honest commit→open→verify must round-trip at the wide digest.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// The pinned commit-and-open test's polynomial variable count. A
    /// non-hiding commit draws no randomness at any step, so fixing it
    /// alongside <see cref="PinnedMleSalt"/> and <see cref="PinnedPointSalt"/>
    /// fully determines the evaluation table and the point by integer
    /// arithmetic, which is what makes an exact-byte pin meaningful here; a
    /// hiding scheme could only be pinned by length.
    /// </summary>
    private const int PinnedVariableCount = 3;
    /// <summary>The salt the pinned test writes its evaluation table from, by fixed integer arithmetic.</summary>
    private const int PinnedMleSalt = 1;
    /// <summary>The salt the pinned test writes its evaluation point from, by fixed integer arithmetic.</summary>
    private const int PinnedPointSalt = 5;

    /// <summary>BLAKE3 digest of the pinned commitment bytes rather than the bytes themselves: an opening runs to kilobytes, and a digest reports one flipped byte exactly as loudly at a fraction of the size.</summary>
    private const string PinnedCommitmentDigest = "FBA77D62198058E0D5CA8A6F0EAE31CC40C6A9DDFDCD368A27F3CA74FFE39554";
    /// <summary>BLAKE3 digest of the pinned opening bytes, for the same reason as <see cref="PinnedCommitmentDigest"/>.</summary>
    private const string PinnedOpeningDigest = "E381E5BD8B06F256958D0C214C1148B89DA923F26EE78DB1402166E2B0E20096";


    /// <summary>
    /// Pins the exact bytes an honest commit and open produce at the wired
    /// digest size, so a change to the serialized form is a decision rather
    /// than a side effect. The commitment and the opening are published
    /// artifacts: they travel inside packaged proof files and across the
    /// command-line surface, so a reader on the far side of a version boundary
    /// parses whatever this test lets through.
    /// </summary>
    /// <remarks>
    /// Widths are the reason this pin earns its place. A hash-tree commitment
    /// is one Merkle node wide and its authentication paths are priced by the
    /// configured digest size; those two figures agree under the wired pairing
    /// of a 32-byte hash with a 32-byte scalar, so a change that redefined
    /// either in terms of the other would leave every shipped byte where it is
    /// and stay invisible to a round-trip test, which proves only that the
    /// writer and the reader still agree with each other. Updating a constant
    /// here is correct only once the format change it reports has been shown
    /// to be intended.
    /// </remarks>
    [TestMethod]
    public void CommitmentAndOpeningBytesAreUnchangedAtTheWiredDigestSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(pool);

        using MultilinearExtension mle = BuildRandomMle(PinnedVariableCount, PinnedMleSalt, pool);
        Scalar[] point = BuildPoint(PinnedVariableCount, PinnedPointSalt, pool);

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
                    Assert.AreEqual(
                        PinnedCommitmentDigest,
                        PinnedDigestOf(commitment.AsReadOnlySpan()),
                        "The serialized commitment bytes changed; the wire format moved.");

                    Assert.AreEqual(
                        PinnedOpeningDigest,
                        PinnedDigestOf(opening.AsReadOnlySpan()),
                        "The serialized opening bytes changed; the wire format moved.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Hashes a serialized artifact with BLAKE3 to the hex digest compared against a pinned constant.</summary>
    private static string PinnedDigestOf(ReadOnlySpan<byte> serialized)
    {
        Span<byte> digest = stackalloc byte[WellKnownMerkleHashParameters.DefaultDigestSizeBytes];
        Blake3.Hash(serialized, digest);

        return Convert.ToHexString(digest);
    }


    /// <summary>One byte past the widest digest the path verifier reserves stack space for, where a configuration stops being serviceable.</summary>
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
        using PolynomialCommitmentProvider atCap = NewProvider(BaseMemoryPool.Shared, WellKnownMerkleHashParameters.MaximumDigestSizeBytes);

        Assert.IsNotNull(atCap, "The widest digest the verifier reserves for must stay a legal configuration.");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => NewProvider(BaseMemoryPool.Shared, TooWideDigestSizeBytes),
            "A digest wider than the verifier's reserved stack space must be refused where the provider is wired.");
    }


    /// <summary>Builds a provider at the default digest width using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool)
    {
        return NewProvider(pool, DigestSizeBytes);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="digestSizeBytes">The Merkle digest width in bytes.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool, int digestSizeBytes)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
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
            HashToScalar, pool,
            digestSizeBytes);
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
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.Provider.Test"u8;
}
