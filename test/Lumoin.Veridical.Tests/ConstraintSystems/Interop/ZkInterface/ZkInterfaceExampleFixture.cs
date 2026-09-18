using System;
using System.IO;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Loads the vendored <c>example.zkif</c> sample; see
/// <c>ConstraintSystems/Interop/ZkInterface/Fixtures/FIXTURES.md</c> for its licence and contents.
/// </summary>
internal static class ZkInterfaceExampleFixture
{
    /// <summary>
    /// The repository-relative directory holding the vendored ZkInterface
    /// fixture files.
    /// </summary>
    private const string FixtureDirectoryRelative = "ConstraintSystems/Interop/ZkInterface/Fixtures";

    /// <summary>
    /// The vendored example file's name within
    /// <see cref="FixtureDirectoryRelative"/>.
    /// </summary>
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
                $"Fixture file not found: {path}. See Fixtures/FIXTURES.md.");
        }

        return File.ReadAllBytes(path);
    }
}
