using Lumoin.Veridical.Core;
using Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;
using System;
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
    //Keeps the normal CI leg fast: enough of the deterministic sweep to sample the front of
    //every mutation family without paying for the full few-hundred-variant sweep every run.
    private const int SmokeMutationCount = 32;

    private const string CircomFixtureDirectoryRelative = "ConstraintSystems/Interop/Circom/Fixtures";
    private const string ZkInterfaceFixtureDirectoryRelative = "ConstraintSystems/Interop/ZkInterface/Fixtures";
    private const string LongfellowAnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-output.txt";

    //The compressed-round-poly and raw-r1cs-witness targets have no natural seed file; their
    //edge-case inputs are sized against the wired curves' scalar width (both BLS12-381 and
    //BN254 use the same 32-byte canonical scalar).
    private const int ScalarSizeBytesForFuzzing = WellKnownCurves.Bls12Curve381ScalarSizeBytes;

    //Matches DecoderFuzzTargets' compressed-round-poly wiring (degree 3, Spartan's outer
    //sumcheck), so the edge-case buffer length lines up with what FromCompressedBytes expects.
    private const int RoundPolynomialDegreeForFuzzing = 3;
    private const int RoundPolynomialLengthHint = RoundPolynomialDegreeForFuzzing * ScalarSizeBytesForFuzzing;
    private const int WitnessLengthHint = ScalarSizeBytesForFuzzing;

    private static readonly string[] ExternalParserTargetNames =
    [
        "circom-r1cs",
        "circom-wtns",
        "zkinterface-decoder",
        "zkinterface-r1cs",
        "zkinterface-wtns",
        "longfellow-circuit",
    ];


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
        _ => throw new ArgumentException($"No seed corpus wired for fuzz target '{targetName}'.", nameof(targetName)),
    };


    //poseidon2.r1cs alone under-covers the header's own count fields: the real
    //circom-compiled file places the constraint section first, so the header's fixed-offset
    //nWires/nConstraints sit tens of kilobytes in, past every mutation family's reach. The
    //small hand-crafted multiplier2 fixtures (already committed for CircomR1csReaderTests)
    //put the header section at the front, so the near-the-start mutation families reach it.
    private static IReadOnlyList<byte[]> CircomR1csSeeds() =>
    [
        LoadCircomFixtureBytes("bls12_381", "poseidon2.r1cs"),
        LoadCircomFixtureBytes("bn254", "poseidon2.r1cs"),
        CircomR1csFixtures.Multiplier2Bytes,
        CircomR1csFixtures.Bn254Multiplier2Bytes,
    ];


    private static IReadOnlyList<byte[]> CircomWitnessSeeds() =>
    [
        LoadCircomFixtureBytes("bls12_381", "poseidon2.wtns"),
        LoadCircomFixtureBytes("bn254", "poseidon2.wtns"),
        CircomWitnessFixtures.Multiplier2Bytes,
    ];


    private static IReadOnlyList<byte[]> ZkInterfaceSeeds() =>
    [
        LoadZkInterfaceExampleBytes(),
        LoadZkInterfaceFixtureBytes("bls12_381"),
        LoadZkInterfaceFixtureBytes("bn254"),
    ];


    private static IReadOnlyList<byte[]> LongfellowSeeds() => [LoadLongfellowSmallSerializedSeed()];


    private static IReadOnlyList<byte[]> EdgeCaseSeeds(int lengthHint) => [.. DeterministicMutations.EdgeCaseInputs(lengthHint)];


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
            Assert.Inconclusive($"Fixture file not found: {path}. Regenerate from the owned source per Fixtures/REGENERATE.md.");
        }

        return File.ReadAllBytes(path);
    }


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
            Assert.Inconclusive($"Fixture file not found: {path}. Regenerate per Fixtures/REGENERATE.md.");
        }

        return File.ReadAllBytes(path);
    }


    //Reuses the small, provably-real serialized circuit LongfellowCircuitReaderTests anchors as
    //"small_serialized" (produced by the reference generate_circuit tool, see that file's
    //TheImportedSmallCircuitDrivesTheProverAndVerifier) rather than the ~99 MB mdoc bundle: it
    //exercises the identical TryRead parse path while keeping a many-hundred-mutation sweep fast.
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
