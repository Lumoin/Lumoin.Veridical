using System;
using System.IO;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Loads the vendored upstream <c>example.zkif</c> sample. Provenance,
/// contents, and the SHA-256 are recorded in
/// <c>ConstraintSystems/Interop/ZkInterface/Fixtures/FIXTURES.md</c>.
/// </summary>
internal static class ZkInterfaceExampleFixture
{
    private const string FixtureDirectoryRelative = "ConstraintSystems/Interop/ZkInterface/Fixtures";
    private const string ExampleFileName = "example.zkif";


    /// <summary>The 648-byte upstream sample: CircuitHeader, ConstraintSystem, Witness.</summary>
    public static byte[] ExampleBytes()
    {
        string directory = Path.Combine(AppContext.BaseDirectory, FixtureDirectoryRelative);
        if(!Directory.Exists(directory))
        {
            //Fall back to repo-relative when the test host does not copy
            //AppContext.BaseDirectory's parallel folders (some MTP configs).
            directory = FixtureDirectoryRelative;
        }

        string path = Path.Combine(directory, ExampleFileName);
        if(!File.Exists(path))
        {
            Assert.Inconclusive(
                $"Fixture file not found: {path}. It is vendored from QED-it/zkinterface; see Fixtures/FIXTURES.md.");
        }

        return File.ReadAllBytes(path);
    }
}
