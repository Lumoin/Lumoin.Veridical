using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Globalization;
using System.IO;

namespace Lumoin.Veridical.Benchmarks.Commitments.Longfellow;

/// <summary>
/// Dumps OUR dual-field mdoc <c>ZkProof</c> envelope (<c>LongfellowMdocProver</c> over the real mdoc-00 credential)
/// to a file for the REVERSE Docker interop gate: the C++ harness <c>mdoc_reverse_verify.cc</c> feeds it to
/// Google's <c>run_mdoc_verifier</c> (ours -> theirs, the mirror of the crown gate's theirs -> ours). The envelope
/// is the validated one the prove-driver gate produces (<see cref="LongfellowMdocProveDriverTests.ReverseGateEnvelope"/>);
/// the file IO lives here in the Benchmarks project, never in the test project (the no-IO-in-tests discipline).
/// </summary>
/// <remarks>
/// Run with the working directory set to the Tests bin output dir so the credential fixture's CWD-relative path
/// (<c>../../../TestMaterial/...</c>) resolves: e.g.
/// <c>cd test/Lumoin.Veridical.Tests/bin/Release/net10.0 &amp;&amp; &lt;benchmarks exe&gt; --mdoc-reverse-dump &lt;abs path&gt;</c>.
/// </remarks>
internal static class MdocReverseDumpDriver
{
    public static void Run(string outputPath)
    {
        byte[] envelope = LongfellowMdocProveDriverTests.ReverseGateEnvelope();
        File.WriteAllBytes(outputPath, envelope);
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "Wrote {0} envelope bytes to {1}", envelope.Length, outputPath));
    }
}
