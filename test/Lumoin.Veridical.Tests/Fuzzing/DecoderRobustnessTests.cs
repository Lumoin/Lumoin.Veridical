using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Lumoin.Veridical.Tests.Fuzzing;

/// <summary>
/// Drives every registered <see cref="DecoderFuzzTargets"/> entry with its seed corpus and
/// deterministic mutations of it, asserting each decoder either succeeds or throws only its
/// documented rejection exception. An unexpected exception (an out-of-range index, an
/// overflow, a null reference, or anything else not listed in
/// <see cref="FuzzTarget.ExpectedRejections"/>) fails the test with the reproducing input's
/// hex bytes so the crash can be replayed.
/// </summary>
[TestClass]
internal sealed class DecoderRobustnessTests
{
    /// <summary>
    /// Keeps the normal CI leg fast: enough of the deterministic sweep to sample the front of
    /// every mutation family without paying for the full few-hundred-variant sweep every run.
    /// </summary>
    private const int SmokeMutationCount = 32;

    /// <summary>
    /// The Circom fixture directory, relative to the test project.
    /// </summary>
    private const string CircomFixtureDirectoryRelative = "ConstraintSystems/Interop/Circom/Fixtures";

    /// <summary>
    /// The zkInterface fixture directory, relative to the test project.
    /// </summary>
    private const string ZkInterfaceFixtureDirectoryRelative = "ConstraintSystems/Interop/ZkInterface/Fixtures";

    /// <summary>
    /// The path, relative to the test project, of the Longfellow circuit anchor that records the
    /// small serialized circuit seed.
    /// </summary>
    private const string LongfellowAnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-output.txt";

    /// <summary>
    /// The compressed-round-poly and raw-r1cs-witness targets have no natural seed file; their
    /// edge-case inputs are sized against the wired curves' scalar width, since BLS12-381 and
    /// BN254 share the same 32-byte canonical scalar.
    /// </summary>
    private const int ScalarSizeBytesForFuzzing = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    /// <summary>
    /// Matches <see cref="DecoderFuzzTargets"/>' compressed-round-poly wiring (degree 3,
    /// Spartan's outer sumcheck), so the edge-case buffer length lines up with what
    /// <c>FromCompressedBytes</c> expects.
    /// </summary>
    private const int RoundPolynomialDegreeForFuzzing = 3;

    /// <summary>
    /// The edge-case input length, in bytes, sized to a degree-<see cref="RoundPolynomialDegreeForFuzzing"/>
    /// compressed round polynomial.
    /// </summary>
    private const int RoundPolynomialLengthHint = RoundPolynomialDegreeForFuzzing * ScalarSizeBytesForFuzzing;

    /// <summary>
    /// The edge-case input length, in bytes, sized to one raw R1CS witness scalar.
    /// </summary>
    private const int WitnessLengthHint = ScalarSizeBytesForFuzzing;

    /// <summary>
    /// The fuzz target names whose full mutation sweep runs against real external-format
    /// decoders (Circom, zkInterface, and the Longfellow circuit reader), gating
    /// <see cref="FullMutationSweepProducesOnlyDocumentedRejections"/> to only those targets.
    /// </summary>
    private static string[] ExternalParserTargetNames { get; } =
    [
        "circom-r1cs",
        "circom-wtns",
        "zkinterface-decoder",
        "zkinterface-r1cs",
        "zkinterface-wtns",
        "longfellow-circuit",
    ];


    /// <summary>
    /// Verifies that the fuzz target registry is non-empty and that every registered target has
    /// a unique name.
    /// </summary>
    [TestMethod]
    public void RegistryIsNonEmptyWithUniqueNames()
    {
        IReadOnlyList<FuzzTarget> targets = DecoderFuzzTargets.All;

        Assert.IsGreaterThan(0, targets.Count, "The fuzz target registry must not be empty.");

        var seenNames = new HashSet<string>(StringComparer.Ordinal);
        foreach(FuzzTarget target in targets)
        {
            Assert.IsTrue(seenNames.Add(target.Name), $"Duplicate fuzz target name '{target.Name}'.");
        }
    }


    /// <summary>
    /// Runs a fast, fixed-size sample of the deterministic mutation sweep against the named
    /// fuzz target's seed corpus, asserting every input either succeeds or throws only a
    /// documented rejection.
    /// </summary>
    /// <param name="targetName">The registered fuzz target's name.</param>
    [TestMethod]
    [DataRow("circom-r1cs")]
    [DataRow("circom-wtns")]
    [DataRow("zkinterface-decoder")]
    [DataRow("zkinterface-r1cs")]
    [DataRow("zkinterface-wtns")]
    [DataRow("longfellow-circuit")]
    [DataRow("bls-g1-oncurve")]
    [DataRow("bls-g2-oncurve")]
    [DataRow("bn254-g1-oncurve")]
    [DataRow("bn254-g2-oncurve")]
    [DataRow("compressed-round-poly")]
    [DataRow("raw-r1cs-witness")]
    [DataRow("bbs-commitment-with-proof")]
    [DataRow("bbs-blind-proof")]
    public void SmokeSweepProducesOnlyDocumentedRejections(string targetName)
    {
        FuzzTarget target = ResolveTarget(targetName);
        IReadOnlyList<byte[]> seeds = LoadSeedCorpus(targetName);

        foreach(byte[] seed in seeds)
        {
            AssertOnlyDocumentedRejection(target, seed);

            for(int mutationIndex = 0; mutationIndex < SmokeMutationCount; mutationIndex++)
            {
                byte[] mutated = DeterministicMutations.Mutate(seed, mutationIndex);
                AssertOnlyDocumentedRejection(target, mutated);
            }
        }
    }


    /// <summary>
    /// Runs the full deterministic mutation sweep against one of the external-parser fuzz
    /// targets' seed corpus, asserting every input either succeeds or throws only a documented
    /// rejection.
    /// </summary>
    /// <param name="targetName">
    /// The registered fuzz target's name; must be one of <see cref="ExternalParserTargetNames"/>.
    /// </param>
    [TestMethod]
    [TestCategory("Slow")]
    [DataRow("circom-r1cs")]
    [DataRow("circom-wtns")]
    [DataRow("zkinterface-decoder")]
    [DataRow("zkinterface-r1cs")]
    [DataRow("zkinterface-wtns")]
    [DataRow("longfellow-circuit")]
    public void FullMutationSweepProducesOnlyDocumentedRejections(string targetName)
    {
        Assert.IsTrue(ExternalParserTargetNames.Contains(targetName), $"'{targetName}' is not one of the external-parser targets this sweep covers.");

        FuzzTarget target = ResolveTarget(targetName);
        IReadOnlyList<byte[]> seeds = LoadSeedCorpus(targetName);

        foreach(byte[] seed in seeds)
        {
            for(int mutationIndex = 0; mutationIndex < DeterministicMutations.MutationCount; mutationIndex++)
            {
                byte[] mutated = DeterministicMutations.Mutate(seed, mutationIndex);
                AssertOnlyDocumentedRejection(target, mutated);
            }
        }
    }


    /// <summary>
    /// Invokes <paramref name="target"/> on <paramref name="input"/> and fails the test if it
    /// throws an exception that is not one of the target's documented rejection types.
    /// </summary>
    /// <param name="target">The fuzz target to invoke.</param>
    /// <param name="input">The input bytes to feed to the target.</param>
    private static void AssertOnlyDocumentedRejection(FuzzTarget target, byte[] input)
    {
        string? failureMessage = null;

        try
        {
            target.Invoke(input);
        }
        catch(Exception exception)
        {
            if(!IsDocumentedRejection(exception, target.ExpectedRejections))
            {
                failureMessage =
                    $"Fuzz finding in {target.Name}: unexpected {exception.GetType().FullName} on input " +
                    $"{Convert.ToHexStringLower(input)}. Message: {exception.Message}";
            }
        }

        if(failureMessage is not null)
        {
            Assert.Fail(failureMessage);
        }
    }


    /// <summary>
    /// Determines whether <paramref name="exception"/> is an instance of one of the
    /// <paramref name="expectedRejections"/> types.
    /// </summary>
    /// <param name="exception">The exception to classify.</param>
    /// <param name="expectedRejections">The documented rejection types to check against.</param>
    /// <returns><see langword="true"/> if the exception matches one of the expected types.</returns>
    private static bool IsDocumentedRejection(Exception exception, Type[] expectedRejections)
    {
        foreach(Type expected in expectedRejections)
        {
            if(expected.IsInstanceOfType(exception))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Looks up the registered fuzz target with the given name.
    /// </summary>
    /// <param name="targetName">The registered fuzz target's name.</param>
    /// <returns>The matching <see cref="FuzzTarget"/>.</returns>
    /// <exception cref="ArgumentException">No target is registered under that name.</exception>
    private static FuzzTarget ResolveTarget(string targetName)
    {
        foreach(FuzzTarget target in DecoderFuzzTargets.All)
        {
            if(string.Equals(target.Name, targetName, StringComparison.Ordinal))
            {
                return target;
            }
        }

        throw new ArgumentException($"No fuzz target named '{targetName}' is registered.", nameof(targetName));
    }


    /// <summary>
    /// Resolves the seed corpus for the named fuzz target, dispatching to the target-specific
    /// seed builder.
    /// </summary>
    /// <param name="targetName">The registered fuzz target's name.</param>
    /// <returns>The seed inputs for that target.</returns>
    private static IReadOnlyList<byte[]> LoadSeedCorpus(string targetName) => targetName switch
    {
        "circom-r1cs" => CircomR1csSeeds(),
        "circom-wtns" => CircomWitnessSeeds(),
        "zkinterface-decoder" => ZkInterfaceSeeds(),
        "zkinterface-r1cs" => ZkInterfaceSeeds(),
        "zkinterface-wtns" => ZkInterfaceSeeds(),
        "longfellow-circuit" => LongfellowSeeds(),
        "bls-g1-oncurve" => EdgeCaseSeeds(WellKnownCurves.Bls12Curve381G1CompressedSizeBytes),
        "bls-g2-oncurve" => EdgeCaseSeeds(WellKnownCurves.Bls12Curve381G2CompressedSizeBytes),
        "bn254-g1-oncurve" => EdgeCaseSeeds(WellKnownCurves.Bn254G1CompressedSizeBytes),
        "bn254-g2-oncurve" => EdgeCaseSeeds(WellKnownCurves.Bn254G2CompressedSizeBytes),
        "compressed-round-poly" => EdgeCaseSeeds(RoundPolynomialLengthHint),
        "raw-r1cs-witness" => EdgeCaseSeeds(WitnessLengthHint),
        "bbs-commitment-with-proof" => BbsCommitmentWithProofSeeds(),
        "bbs-blind-proof" => BbsBlindProofSeeds(),
        _ => throw new ArgumentException($"No seed corpus wired for fuzz target '{targetName}'.", nameof(targetName)),
    };


    /// <summary>
    /// Builds the seed corpus for the <c>bbs-commitment-with-proof</c> fuzz target: a hand-built,
    /// well-formed container (a generator-point filler with unit scalars) paired with the sized
    /// edge-case inputs, since that format has no natural fixture file to seed from. Seeding from
    /// a passing baseline lets the mutation families exercise the frame arithmetic rather than
    /// only immediate rejections.
    /// </summary>
    /// <returns>The seed inputs for the <c>bbs-commitment-with-proof</c> target.</returns>
    private static IReadOnlyList<byte[]> BbsCommitmentWithProofSeeds()
    {
        byte[] seed = new byte[BbsCommitmentWithProof.ComputeSizeBytes(committedMessageCount: 1)];
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381)
            .CopyTo(seed.AsSpan(BbsCommitmentWithProof.COffset, BbsCommitmentWithProof.CSizeBytes));
        for(int offset = BbsCommitmentWithProof.SHatOffset; offset < seed.Length; offset += BbsCommitmentWithProof.ScalarSizeBytes)
        {
            seed[offset + BbsCommitmentWithProof.ScalarSizeBytes - 1] = 1;
        }

        return [seed, .. DeterministicMutations.EdgeCaseInputs(BbsCommitmentWithProof.MinimumSizeBytes)];
    }


    /// <summary>
    /// Builds the seed corpus for the <c>bbs-blind-proof</c> fuzz target: a hand-built,
    /// well-formed blind proof (see <see cref="BuildBlindProofSeed"/>) paired with the sized
    /// edge-case inputs, since that format has no natural fixture file to seed from.
    /// </summary>
    /// <returns>The seed inputs for the <c>bbs-blind-proof</c> target.</returns>
    private static IReadOnlyList<byte[]> BbsBlindProofSeeds() =>
        [BuildBlindProofSeed(), .. DeterministicMutations.EdgeCaseInputs(BbsBlindProof.MinimumSizeBytes)];


    /// <summary>
    /// A well-formed framed blind proof with zero undisclosed messages,
    /// one disclosed index, and one committed disclosure — the smallest
    /// shape that populates all four frames.
    /// </summary>
    private static byte[] BuildBlindProofSeed()
    {
        ReadOnlySpan<byte> pointFiller = WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381);
        int coreProofSizeBytes = BbsProof.MinimumSizeBytes;
        byte[] seed = new byte[BbsBlindProof.ComputeSizeBytes(undisclosedMessageCount: 0, disclosedIndexCount: 1, committedDisclosureCount: 1)];
        Span<byte> cursor = seed;

        BinaryPrimitives.WriteInt64BigEndian(cursor, coreProofSizeBytes);
        cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
        pointFiller.CopyTo(cursor[BbsProof.ABarOffset..]);
        pointFiller.CopyTo(cursor[BbsProof.BBarOffset..]);
        pointFiller.CopyTo(cursor[BbsProof.DOffset..]);
        //The four fixed scalar slots (e^, r1^, r3^, challenge), each set to 1.
        for(int i = 0; i < 4; i++)
        {
            cursor[BbsProof.EHatOffset + BbsProof.ScalarSizeBytes * (i + 1) - 1] = 1;
        }
        cursor = cursor[coreProofSizeBytes..];

        BinaryPrimitives.WriteInt64BigEndian(cursor, 1);
        cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
        BinaryPrimitives.WriteInt64BigEndian(cursor, 0);
        cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];

        BinaryPrimitives.WriteInt64BigEndian(cursor, 1);
        cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
        pointFiller.CopyTo(cursor);
        cursor = cursor[BbsBlindProof.CommittedDisclosurePointSizeBytes..];
        cursor[BbsBlindProof.CommittedDisclosureScalarSizeBytes - 1] = 1;
        cursor = cursor[BbsBlindProof.CommittedDisclosureScalarSizeBytes..];

        BinaryPrimitives.WriteInt64BigEndian(cursor, 1);
        cursor = cursor[BbsBlindProof.Int64FieldSizeBytes..];
        BinaryPrimitives.WriteInt64BigEndian(cursor, 1);

        return seed;
    }


    /// <summary>
    /// Builds the seed corpus for the <c>circom-r1cs</c> fuzz target from the committed Circom
    /// R1CS fixtures. The <c>poseidon2.r1cs</c> fixtures alone under-cover the header's own
    /// count fields, because a Circom-compiled file places the constraint section first, so the
    /// header's fixed-offset <c>nWires</c>/<c>nConstraints</c> sit tens of kilobytes in, past
    /// every mutation family's reach; the small hand-crafted multiplier2 fixtures (also used by
    /// <c>CircomR1csReaderTests</c>) put the header section at the front, so the near-the-start
    /// mutation families reach it.
    /// </summary>
    /// <returns>The seed inputs for the <c>circom-r1cs</c> target.</returns>
    private static IReadOnlyList<byte[]> CircomR1csSeeds() =>
    [
        LoadCircomFixtureBytes("bls12_381", "poseidon2.r1cs"),
        LoadCircomFixtureBytes("bn254", "poseidon2.r1cs"),
        CircomR1csFixtures.Multiplier2Bytes,
        CircomR1csFixtures.Bn254Multiplier2Bytes,
    ];


    /// <summary>
    /// Builds the seed corpus for the <c>circom-wtns</c> fuzz target from the committed Circom
    /// witness fixtures.
    /// </summary>
    /// <returns>The seed inputs for the <c>circom-wtns</c> target.</returns>
    private static IReadOnlyList<byte[]> CircomWitnessSeeds() =>
    [
        LoadCircomFixtureBytes("bls12_381", "poseidon2.wtns"),
        LoadCircomFixtureBytes("bn254", "poseidon2.wtns"),
        CircomWitnessFixtures.Multiplier2Bytes,
    ];


    /// <summary>
    /// Builds the seed corpus shared by the zkInterface fuzz targets from the committed
    /// zkInterface example and per-curve fixtures.
    /// </summary>
    /// <returns>The seed inputs shared by the zkInterface targets.</returns>
    private static IReadOnlyList<byte[]> ZkInterfaceSeeds() =>
    [
        LoadZkInterfaceExampleBytes(),
        LoadZkInterfaceFixtureBytes("bls12_381"),
        LoadZkInterfaceFixtureBytes("bn254"),
    ];


    /// <summary>
    /// Builds the seed corpus for the <c>longfellow-circuit</c> fuzz target from the small
    /// serialized circuit seed.
    /// </summary>
    /// <returns>The seed inputs for the <c>longfellow-circuit</c> target.</returns>
    private static IReadOnlyList<byte[]> LongfellowSeeds() => [LoadLongfellowSmallSerializedSeed()];


    /// <summary>
    /// Builds a seed corpus of only the deterministic edge-case inputs, for targets with no
    /// natural fixture file.
    /// </summary>
    /// <param name="lengthHint">The input length, in bytes, the edge cases are sized to.</param>
    /// <returns>The edge-case seed inputs.</returns>
    private static IReadOnlyList<byte[]> EdgeCaseSeeds(int lengthHint) => [.. DeterministicMutations.EdgeCaseInputs(lengthHint)];


    /// <summary>
    /// Reads a committed Circom fixture file's raw bytes for the given curve.
    /// </summary>
    /// <param name="curveDirectory">The curve-named subdirectory under the Circom fixture directory.</param>
    /// <param name="fileName">The fixture file's name.</param>
    /// <returns>The fixture file's raw bytes.</returns>
    private static byte[] LoadCircomFixtureBytes(string curveDirectory, string fileName)
    {
        string directory = Path.Combine(AppContext.BaseDirectory, CircomFixtureDirectoryRelative, curveDirectory);
        if(!Directory.Exists(directory))
        {
            //Fall back to repo-relative when the test host does not copy AppContext.BaseDirectory's
            //parallel test folders (some MTP configs), mirroring CircomPoseidonFixtureTests.
            directory = Path.Combine(CircomFixtureDirectoryRelative, curveDirectory);
        }

        string path = Path.Combine(directory, fileName);
        if(!File.Exists(path))
        {
            Assert.Inconclusive($"Fixture file not found: {path}. Restore the committed fixture bytes.");
        }

        return File.ReadAllBytes(path);
    }


    /// <summary>
    /// Reads the vendored zkInterface example fixture's raw bytes.
    /// </summary>
    /// <returns>The example fixture's raw bytes.</returns>
    private static byte[] LoadZkInterfaceExampleBytes()
    {
        string directory = Path.Combine(AppContext.BaseDirectory, ZkInterfaceFixtureDirectoryRelative);
        if(!Directory.Exists(directory))
        {
            directory = ZkInterfaceFixtureDirectoryRelative;
        }

        string path = Path.Combine(directory, "example.zkif");
        if(!File.Exists(path))
        {
            Assert.Inconclusive($"Fixture file not found: {path}. It is vendored from QED-it/zkinterface; see Fixtures/FIXTURES.md.");
        }

        return File.ReadAllBytes(path);
    }


    /// <summary>
    /// Reads a committed zkInterface fixture file's raw bytes for the given curve.
    /// </summary>
    /// <param name="curveDirectory">The curve-named subdirectory under the zkInterface fixture directory.</param>
    /// <returns>The fixture file's raw bytes.</returns>
    private static byte[] LoadZkInterfaceFixtureBytes(string curveDirectory)
    {
        string directory = Path.Combine(AppContext.BaseDirectory, ZkInterfaceFixtureDirectoryRelative, curveDirectory);
        if(!Directory.Exists(directory))
        {
            directory = Path.Combine(ZkInterfaceFixtureDirectoryRelative, curveDirectory);
        }

        string path = Path.Combine(directory, "multiplier2.zkif");
        if(!File.Exists(path))
        {
            Assert.Inconclusive($"Fixture file not found: {path}. Restore the committed fixture bytes.");
        }

        return File.ReadAllBytes(path);
    }


    /// <summary>
    /// Loads the small, genuine serialized circuit that
    /// <see cref="Lumoin.Veridical.Tests.Algebraic.LongfellowCircuitReaderTests.TheImportedSmallCircuitDrivesTheProverAndVerifier"/>
    /// also exercises, rather than the full ~99 MB multi-attribute mdoc bundle, so this sweep can
    /// run the identical <c>TryRead</c> parse path many hundreds of times while staying fast.
    /// </summary>
    /// <returns>The small serialized circuit's raw bytes.</returns>
    private static byte[] LoadLongfellowSmallSerializedSeed()
    {
        string path = $"../../../{LongfellowAnchorRelativePath}";
        if(!File.Exists(path))
        {
            Assert.Inconclusive($"Anchor file not found: {path}.");
        }

        var anchors = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            if(line.Length == 0)
            {
                continue;
            }

            foreach(string token in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                int separator = token.IndexOf('=', StringComparison.Ordinal);
                if(separator < 0)
                {
                    continue;
                }

                anchors[token[..separator]] = token[(separator + 1)..];
            }
        }

        if(!anchors.TryGetValue("small_serialized", out string? smallSerializedHex))
        {
            Assert.Inconclusive($"Anchor key 'small_serialized' not found in {path}.");

            return [];
        }

        return Convert.FromHexString(smallSerializedHex);
    }
}
