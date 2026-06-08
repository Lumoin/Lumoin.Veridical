using Lumoin.Veridical.Cli;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// In-process tests of the shared <see cref="VeridicalOperations"/> the CLI and
/// the MCP tools both call. These run without spawning a subprocess, so they are
/// fast and always execute (no dependency on the built executable).
/// </summary>
[TestClass]
internal sealed class VeridicalOperationsTests
{
    //Official BLAKE3 test vectors (256-bit, lowercase hex).
    private const string Blake3EmptyHash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";


    [TestMethod]
    public void InfoReportsPlatformAndBothCurveBackends()
    {
        string info = VeridicalOperations.Info();

        Assert.Contains("OS:", info, StringComparison.Ordinal);
        Assert.Contains("Architecture:", info, StringComparison.Ordinal);
        Assert.Contains("BLS12-381 scalar backend:", info, StringComparison.Ordinal);
        Assert.Contains("BN254 scalar backend:", info, StringComparison.Ordinal);
    }


    [TestMethod]
    public void HashBlake3OfEmptyMatchesKnownVector()
    {
        string digest = VeridicalOperations.HashBlake3(ReadOnlySpan<byte>.Empty);

        Assert.AreEqual(Blake3EmptyHash, digest);
    }


    [TestMethod]
    public void HashBlake3TextMatchesHashOfItsUtf8Bytes()
    {
        string viaText = VeridicalOperations.HashBlake3Text("hello");
        string viaBytes = VeridicalOperations.HashBlake3(Encoding.UTF8.GetBytes("hello"));

        Assert.AreEqual(viaBytes, viaText);
        //64 lowercase hex characters for a 32-byte digest.
        Assert.AreEqual(64, viaText.Length);
    }


    [TestMethod]
    public void SelfTestPassesAllConformanceVectors()
    {
        (bool ok, string report) = VeridicalOperations.RunSelfTest();

        Assert.IsTrue(ok, $"Self-test must pass on this host. Report:\n{report}");
        Assert.Contains("All conformance vectors passed.", report, StringComparison.Ordinal);
        Assert.DoesNotContain("[FAIL]", report, StringComparison.Ordinal);
    }
}
