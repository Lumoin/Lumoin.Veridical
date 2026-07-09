using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The committed Longfellow fixtures are pinned to google/longfellow-zk commit
/// <c>d8ad8f65187c7c364a3c2181ad484bcab03f0ec2</c> (v0.9 plus 90 commits, 2026-05-29). The ZkSpec registry
/// identity and the raw-stream digest recorded in the circuit-import anchor are asserted here against the
/// documented pin, so a fixture regeneration from a different upstream state fails the default suite rather
/// than drifting silently. See <c>TestMaterial/Longfellow/PROVENANCE.md</c> and the "Longfellow upstream pin"
/// section of <c>SECURITY.md</c> for the full identity chain and the re-pin tripwires.
/// </summary>
[TestClass]
internal sealed class LongfellowUpstreamPinTests
{
    private const string AnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-output.txt";
    private const string CrownAnchorRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";

    private const string PinnedZkSpecSystem = "longfellow-libzk-v1";
    private const int PinnedZkSpecVersion = 7;
    private const int PinnedZkSpecAttributeCount = 1;
    private const int PinnedBlockEncodedHash = 4151;
    private const int PinnedBlockEncodedSignature = 4096;
    private const string PinnedCanonicalCircuitHash = "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121";
    private const string PinnedRawCircuitSha256 = "332e3a96826a5f1a7a745dc9acac82e4a38051ee435877f95cdba71493354835";
    private const int PinnedProofSpecVersion = 7;


    [TestMethod]
    public void TheCircuitAnchorPinsTheDocumentedZkSpecIdentity()
    {
        Dictionary<string, string> anchor = LoadAnchors(AnchorRelativePath);

        Assert.AreEqual(PinnedZkSpecSystem, anchor["zkspec_system"], "The pinned ZkSpec system must match the documented upstream pin.");
        Assert.AreEqual(PinnedZkSpecVersion, AnchorInt(anchor, "zkspec_version"), "The pinned ZkSpec version must match the documented upstream pin.");
        Assert.AreEqual(PinnedZkSpecAttributeCount, AnchorInt(anchor, "zkspec_num_attributes"), "The pinned ZkSpec attribute count must match the documented upstream pin.");
        Assert.AreEqual(PinnedBlockEncodedHash, AnchorInt(anchor, "zkspec_block_enc_hash"), "The pinned ZkSpec block_enc hash size must match the documented upstream pin.");
        Assert.AreEqual(PinnedBlockEncodedSignature, AnchorInt(anchor, "zkspec_block_enc_sig"), "The pinned ZkSpec block_enc signature size must match the documented upstream pin.");
        Assert.AreEqual(PinnedCanonicalCircuitHash, anchor["zkspec_pinned_circuit_hash"], "The pinned ZkSpec circuit_hash registry key must match the documented upstream pin.");
    }


    [TestMethod]
    public void TheCircuitAnchorPinsTheDocumentedRawStreamDigest()
    {
        Dictionary<string, string> anchor = LoadAnchors(AnchorRelativePath);

        Assert.AreEqual(PinnedRawCircuitSha256, anchor["raw_rawsha"], "The decompressed raw circuit stream digest must match the documented upstream pin.");
    }


    [TestMethod]
    public void TheCrownProofFixtureCarriesThePinnedSpecVersion()
    {
        Dictionary<string, string> anchor = LoadAnchors(CrownAnchorRelativePath);

        Assert.AreEqual(PinnedProofSpecVersion, AnchorInt(anchor, "version"), "The crown proof fixture's ZkSpec version must match the documented upstream pin.");
    }


    private static int AnchorInt(Dictionary<string, string> anchor, string key) => int.Parse(anchor[key], CultureInfo.InvariantCulture);


    private static Dictionary<string, string> LoadAnchors(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
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

                map[token[..separator]] = token[(separator + 1)..];
            }
        }

        return map;
    }
}
