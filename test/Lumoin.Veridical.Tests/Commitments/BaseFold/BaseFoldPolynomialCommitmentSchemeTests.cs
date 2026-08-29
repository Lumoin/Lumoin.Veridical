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
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 12;

    //Twice the node width the scalar-wide leaf buffer gives the tree, and the
    //widest digest the Merkle surface admits, so the disagreement is the largest
    //one that is otherwise a legal configuration.
    private const int MismatchedDigestSizeBytes = 2 * WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //Two layers, so the opening carries a fold root and authentication paths -
    //the fields the digest size prices and the tree does not.
    private const int MismatchedDigestVariableCount = 2;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void CommitOpenVerifyRoundTrips(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

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


    [TestMethod]
    public void TamperedOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider();

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


    [TestMethod]
    public void TamperedCommitmentIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider();

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


    [TestMethod]
    public void WrongClaimedValueIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;
        using PolynomialCommitmentProvider provider = NewProvider();

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
    /// A Merkle tree takes its node width from the buffer it is built over and
    /// never sees the configured digest size, while the opening's length
    /// arithmetic prices every root and authentication path at that digest size.
    /// The two are separate figures that coincide only under the wired hash, so
    /// where they disagree the opening must be refused: the buffer would be
    /// written short, every field after the first root would land where the
    /// reader does not look, and the length check on the way back in would still
    /// pass because it prices the sections the same wrong way.
    /// </summary>
    [TestMethod]
    public void OpeningRefusesADigestWidthTheTreeDoesNotCarry()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(MismatchedDigestSizeBytes);

        using MultilinearExtension mle = BuildRandomMle(MismatchedDigestVariableCount, 1, pool);
        Scalar[] point = BuildPoint(MismatchedDigestVariableCount, 5, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();

                Assert.ThrowsExactly<ArgumentException>(
                    () => provider.Open(commitment, blind, mle, point, openTx, pool),
                    "An opening whose Merkle nodes are not the configured digest width must be refused, not serialized into a buffer it cannot fill.");
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    //The commit and open below are fully determined by these two salts: the
    //evaluation table and the point are written from them by fixed integer
    //arithmetic, and a non-hiding commit draws no randomness at any step. That
    //determinism is what makes a content pin meaningful here, and it is why a
    //hiding scheme can only be pinned by length.
    private const int PinnedVariableCount = 3;
    private const int PinnedMleSalt = 1;
    private const int PinnedPointSalt = 5;

    //A digest of the serialized bytes rather than the bytes themselves: an
    //opening runs to kilobytes, and a digest reports one flipped byte exactly
    //as loudly at a fraction of the size.
    private const string PinnedCommitmentDigest = "FBA77D62198058E0D5CA8A6F0EAE31CC40C6A9DDFDCD368A27F3CA74FFE39554";
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
        using PolynomialCommitmentProvider provider = NewProvider();

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


    //Hashes a serialized artifact down to the constant the pin above carries.
    private static string PinnedDigestOf(ReadOnlySpan<byte> serialized)
    {
        Span<byte> digest = stackalloc byte[WellKnownMerkleHashParameters.DefaultDigestSizeBytes];
        Blake3.Hash(serialized, digest);

        return Convert.ToHexString(digest);
    }


    private static PolynomialCommitmentProvider NewProvider()
    {
        return NewProvider(DigestSizeBytes);
    }


    private static PolynomialCommitmentProvider NewProvider(int digestSizeBytes)
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
            HashToScalar,
            digestSizeBytes);
    }


    private static PolynomialCommitment TamperFirstByte(PolynomialCommitment commitment, BaseMemoryPool pool)
    {
        Span<byte> bytes = stackalloc byte[commitment.AsReadOnlySpan().Length];
        commitment.AsReadOnlySpan().CopyTo(bytes);
        bytes[0] ^= 0x01;

        return PolynomialCommitment.FromBytes(bytes, Curve, CommitmentScheme.BaseFold, pool);
    }


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


    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.Provider.Test"u8;
}
