using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// The digest-width round-trip gate: every hash-tree provider commits, opens
/// and verifies across a representative spread of node widths — a truncated
/// half-scalar digest, the wired scalar width, a mid value coinciding with
/// neither figure, and the Merkle surface's cap — with the commitment and
/// the opening each filling exactly the lengths the provider's own sizing
/// seams state. Any width other than the wired scalar width runs the
/// scheme's leaf commitment for real, so this is the gate that keeps the
/// digest size an actual capability rather than a label the serializers
/// price.
/// </summary>
[TestClass]
internal sealed class DigestWidthRoundTripTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>Half the scalar width: the truncated-digest capability the sizing documentation promises.</summary>
    private const int TruncatedDigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes / 2;

    /// <summary>The wired pairing of a 32-byte hash with a 32-byte scalar.</summary>
    private const int DefaultDigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>Neither the scalar width nor the cap, so no coincidence can mask a mispricing.</summary>
    private const int MidDigestSizeBytes = 48;

    /// <summary>The widest digest the Merkle surface admits.</summary>
    private const int WideDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;

    /// <summary>The IOPP query repetitions for the BaseFold family and Ligero.</summary>
    private const int TestQueryCount = 12;

    /// <summary>WHIR's initial inverse-rate exponent: rate 1/4.</summary>
    private const int WhirInitialRateLog2 = 2;

    /// <summary>WHIR's per-round target, the largest whole level the wired shapes place on distinct query cosets.</summary>
    private const int WhirSecurityLevelBits = 24;

    /// <summary>The BaseFold-family and Ligero instance size: enough layers for the opening to carry fold roots and paths.</summary>
    private const int SmallVariableCount = 3;

    /// <summary>The WHIR-family instance size; WHIR cannot open below its folding parameter.</summary>
    private const int WhirVariableCount = 8;

    /// <summary>The deterministic fill's salt for the committed polynomial.</summary>
    private const int MleSalt = 21;

    /// <summary>The deterministic evaluation point's salt.</summary>
    private const int PointSalt = 23;

    /// <summary>The scalar-add backend.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The scalar-subtract backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The scalar-multiply backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The scalar-invert backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The scalar-reduce backend.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The hash-to-scalar backend the BaseFold code derivation uses.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The entropy-sourced scalar sampler the hiding flavours draw from.</summary>
    private static ScalarRandomDelegate ScalarRandom { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The code seed the BaseFold flavours derive their encoder from.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.test.digest-width-gate.code.v1");

    /// <summary>The curve every artifact is tagged with.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// Commit → open → verify at the stated node width, with the commitment
    /// and the opening filling exactly the lengths the provider's sizing
    /// seams state.
    /// </summary>
    /// <param name="schemeName">The factory to exercise.</param>
    /// <param name="digestSizeBytes">The node width to build the provider at.</param>
    [TestMethod]
    [DataRow("ligero", TruncatedDigestSizeBytes)]
    [DataRow("ligero", DefaultDigestSizeBytes)]
    [DataRow("ligero", MidDigestSizeBytes)]
    [DataRow("ligero", WideDigestSizeBytes)]
    [DataRow("basefold", TruncatedDigestSizeBytes)]
    [DataRow("basefold", DefaultDigestSizeBytes)]
    [DataRow("basefold", MidDigestSizeBytes)]
    [DataRow("basefold", WideDigestSizeBytes)]
    [DataRow("zkbasefold", TruncatedDigestSizeBytes)]
    [DataRow("zkbasefold", DefaultDigestSizeBytes)]
    [DataRow("zkbasefold", MidDigestSizeBytes)]
    [DataRow("zkbasefold", WideDigestSizeBytes)]
    [DataRow("whir", TruncatedDigestSizeBytes)]
    [DataRow("whir", DefaultDigestSizeBytes)]
    [DataRow("whir", MidDigestSizeBytes)]
    [DataRow("whir", WideDigestSizeBytes)]
    [DataRow("zkwhir", TruncatedDigestSizeBytes)]
    [DataRow("zkwhir", DefaultDigestSizeBytes)]
    [DataRow("zkwhir", MidDigestSizeBytes)]
    [DataRow("zkwhir", WideDigestSizeBytes)]
    public void CommitOpenVerifyRoundTripsAtTheStatedWidth(string schemeName, int digestSizeBytes)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(pool, schemeName, digestSizeBytes);
        int variableCount = VariableCountFor(schemeName);

        using MultilinearExtension mle = BuildMle(variableCount, pool);
        Scalar[] point = BuildPoint(variableCount, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                Assert.HasCount(digestSizeBytes, commitment.AsReadOnlySpan(), $"The {schemeName} commitment is one Merkle root at the stated node width.");

                PolynomialCommitmentSizeDelegate? commitmentSeam = provider.CommitmentSizeBytes;
                Assert.IsNotNull(commitmentSeam, $"The {schemeName} provider must state its commitment width.");
                Assert.AreEqual(digestSizeBytes, commitmentSeam(variableCount), $"The {schemeName} commitment seam must state the width Commit produces.");

                using FiatShamirTranscript openTx = NewTranscript(schemeName);
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    PolynomialOpeningSizeDelegate? openingSeam = provider.EvaluationProofSizeBytes;
                    Assert.IsNotNull(openingSeam, $"The {schemeName} provider must state its opening length.");
                    Assert.HasCount(openingSeam(variableCount), opening.AsReadOnlySpan(), $"The {schemeName} opening must fill exactly the budget the seam prices at this width.");

                    using FiatShamirTranscript verifyTx = NewTranscript(schemeName);
                    Assert.IsTrue(
                        provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        $"An honest {schemeName} commit→open→verify must round-trip at a {digestSizeBytes}-byte node width.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>
    /// Builds one of the hash-tree providers by name at an explicit digest
    /// size.
    /// </summary>
    /// <param name="schemeName">The factory to build.</param>
    /// <param name="digestSizeBytes">The node width to build it at.</param>
    /// <returns>The provider; the caller owns its disposal.</returns>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool, string schemeName, int digestSizeBytes)
    {
        return schemeName switch
        {
            "ligero" => LigeroPolynomialCommitmentScheme.Create(
                Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce, Hash, Squeeze, Hash, Merkle,
                WellKnownHashAlgorithms.Blake3, digestSizeBytes: digestSizeBytes),
            "basefold" => BaseFoldPolynomialCommitmentScheme.Create(
                CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                HashToScalar, pool, digestSizeBytes),
            "zkbasefold" => ZkBaseFoldPolynomialCommitmentScheme.Create(
                CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                ScalarRandom, HashToScalar, pool, digestSizeBytes),
            "whir" => WhirPolynomialCommitmentScheme.Create(
                Curve, WhirInitialRateLog2, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                securityLevelBits: WhirSecurityLevelBits, digestSizeBytes: digestSizeBytes),
            "zkwhir" => WhirPolynomialCommitmentScheme.CreateZeroKnowledge(
                Curve, WhirInitialRateLog2, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                ScalarRandom, securityLevelBits: WhirSecurityLevelBits, digestSizeBytes: digestSizeBytes),
            _ => throw new ArgumentOutOfRangeException(nameof(schemeName), schemeName, "Unknown scheme name.")
        };
    }


    /// <summary>
    /// The instance size each scheme opens at: WHIR cannot open below its
    /// folding parameter, the others stay small.
    /// </summary>
    /// <param name="schemeName">The scheme the row exercises.</param>
    /// <returns>The variable count to commit at.</returns>
    private static int VariableCountFor(string schemeName)
    {
        return schemeName is "whir" or "zkwhir" ? WhirVariableCount : SmallVariableCount;
    }


    /// <summary>
    /// A fresh transcript under the scheme's own domain label with empty
    /// context.
    /// </summary>
    /// <param name="schemeName">The scheme the transcript drives.</param>
    /// <returns>The transcript; the caller owns its disposal.</returns>
    private static FiatShamirTranscript NewTranscript(string schemeName)
    {
        string label = schemeName switch
        {
            "ligero" => WellKnownLigeroEvaluationLabels.DomainV1,
            "basefold" or "zkbasefold" => WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel,
            "whir" or "zkwhir" => WellKnownWhirParameters.TranscriptDomainLabel,
            _ => throw new ArgumentOutOfRangeException(nameof(schemeName), schemeName, "Unknown scheme name.")
        };

        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(label),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// A deterministic dense MLE over the boolean cube.
    /// </summary>
    /// <param name="variableCount">The polynomial's variable count.</param>
    /// <param name="pool">The pool to rent from.</param>
    /// <returns>The extension; the caller owns its disposal.</returns>
    private static MultilinearExtension BuildMle(int variableCount, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evaluations = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        DeterministicScalarFill.FillCanonical(evaluations, MleSalt, Reduce, Curve);

        return MultilinearExtension.FromEvaluations(evaluations, variableCount, Curve, pool);
    }


    /// <summary>
    /// A deterministic evaluation point, one scalar per variable.
    /// </summary>
    /// <param name="variableCount">The number of coordinates.</param>
    /// <param name="pool">The pool to rent from.</param>
    /// <returns>The point; the caller disposes every coordinate.</returns>
    private static Scalar[] BuildPoint(int variableCount, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int coordinate = 0; coordinate < variableCount; coordinate++)
        {
            wide.Clear();
            BinaryPrimitives.WriteInt32BigEndian(wide[..4], (PointSalt * 59) + (coordinate * 23) + 2);
            BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (PointSalt * 29) + (coordinate * 43) + 5);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            point[coordinate] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return point;
    }


    /// <summary>
    /// Disposes every coordinate of an evaluation point.
    /// </summary>
    /// <param name="point">The point to dispose.</param>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>
    /// The two-to-one compression: BLAKE3 over the concatenated children,
    /// buffered for the widest node the Merkle surface admits and sliced to
    /// the actual input widths, so one compression serves every width this
    /// gate runs; BLAKE3 writes exactly the output's length.
    /// </summary>
    /// <param name="left">The left input.</param>
    /// <param name="right">The right input.</param>
    /// <param name="output">Receives the produced node.</param>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
