using Lumoin.Veridical.Longfellow;
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
    private const string FourAttributeAnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-4attr-output.txt";
    private const string FourAttributeProofAnchorRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-4attr-output.txt";

    private const string PinnedZkSpecSystem = "longfellow-libzk-v1";
    private const int PinnedZkSpecVersion = 7;
    private const int PinnedZkSpecAttributeCount = 1;
    private const int PinnedBlockEncodedHash = 4151;
    private const int PinnedBlockEncodedSignature = 4096;
    private const string PinnedCanonicalCircuitHash = "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121";
    private const string PinnedRawCircuitSha256 = "332e3a96826a5f1a7a745dc9acac82e4a38051ee435877f95cdba71493354835";
    private const int PinnedProofSpecVersion = 7;

    private const int PinnedFourAttributeCount = 4;
    private const int PinnedFourAttributeBlockEncodedHash = 4415;
    private const string PinnedFourAttributeCanonicalCircuitHash = "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460";
    private const string PinnedFourAttributeRawCircuitSha256 = "5a282c3f77d35a32ec5af028ece8c2c8cab612f4aa1d178f7607984dd5787010";

    //The signature circuit is shared by every version-7 attribute count; both circuit anchors must agree on it.
    private const string PinnedSignatureCircuitId = "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d";

    //Each anchor file is parsed once and shared across the pin tests (the proof anchors carry the full
    //envelope hex, so re-parsing per test is avoidable weight).
    private static Dictionary<string, string> CircuitAnchor { get; } = LoadAnchors(AnchorRelativePath);
    private static Dictionary<string, string> CrownAnchor { get; } = LoadAnchors(CrownAnchorRelativePath);
    private static Dictionary<string, string> FourAttributeCircuitAnchor { get; } = LoadAnchors(FourAttributeAnchorRelativePath);
    private static Dictionary<string, string> FourAttributeProofAnchor { get; } = LoadAnchors(FourAttributeProofAnchorRelativePath);


    [TestMethod]
    public void TheCircuitAnchorPinsTheDocumentedZkSpecIdentity()
    {
        Dictionary<string, string> anchor = CircuitAnchor;

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
        Dictionary<string, string> anchor = CircuitAnchor;

        Assert.AreEqual(PinnedRawCircuitSha256, anchor["raw_rawsha"], "The decompressed raw circuit stream digest must match the documented upstream pin.");
    }


    [TestMethod]
    public void TheCrownProofFixtureCarriesThePinnedSpecVersion()
    {
        Dictionary<string, string> anchor = CrownAnchor;

        Assert.AreEqual(PinnedProofSpecVersion, AnchorInt(anchor, "version"), "The crown proof fixture's ZkSpec version must match the documented upstream pin.");
    }


    [TestMethod]
    public void TheFourAttributeCircuitAnchorPinsTheDocumentedZkSpecIdentity()
    {
        Dictionary<string, string> anchor = FourAttributeCircuitAnchor;

        Assert.AreEqual(PinnedZkSpecSystem, anchor["zkspec_system"], "The pinned four-attribute ZkSpec system must match the documented upstream pin.");
        Assert.AreEqual(PinnedZkSpecVersion, AnchorInt(anchor, "zkspec_version"), "The pinned four-attribute ZkSpec version must match the documented upstream pin.");
        Assert.AreEqual(PinnedFourAttributeCount, AnchorInt(anchor, "zkspec_num_attributes"), "The pinned four-attribute ZkSpec attribute count must match the documented upstream pin.");
        Assert.AreEqual(PinnedFourAttributeBlockEncodedHash, AnchorInt(anchor, "zkspec_block_enc_hash"), "The pinned four-attribute ZkSpec block_enc hash size must match the documented upstream pin.");
        Assert.AreEqual(PinnedBlockEncodedSignature, AnchorInt(anchor, "zkspec_block_enc_sig"), "The pinned four-attribute ZkSpec block_enc signature size must match the documented upstream pin.");
        Assert.AreEqual(PinnedFourAttributeCanonicalCircuitHash, anchor["zkspec_pinned_circuit_hash"], "The pinned four-attribute ZkSpec circuit_hash registry key must match the documented upstream pin.");
    }


    [TestMethod]
    public void TheFourAttributeCircuitAnchorPinsTheDocumentedRawStreamDigest()
    {
        Dictionary<string, string> anchor = FourAttributeCircuitAnchor;

        Assert.AreEqual(PinnedFourAttributeRawCircuitSha256, anchor["raw_rawsha"], "The decompressed four-attribute raw circuit stream digest must match the documented upstream pin.");
    }


    [TestMethod]
    public void TheFourAttributeProofFixtureCarriesThePinnedSpecIdentity()
    {
        Dictionary<string, string> anchor = FourAttributeProofAnchor;

        Assert.AreEqual(PinnedProofSpecVersion, AnchorInt(anchor, "version"), "The four-attribute proof fixture's ZkSpec version must match the documented upstream pin.");
        Assert.AreEqual(PinnedFourAttributeCount, AnchorInt(anchor, "num_attributes"), "The four-attribute proof fixture's attribute count must match the documented upstream pin.");
    }


    [TestMethod]
    public void TheSpecRegistryRowsMatchTheReferenceAnchors()
    {
        //The public LongfellowMdocZkSpec rows are the values the facade proves and verifies with; each row
        //is asserted against the reference dump of its bundle so the registry cannot drift from the anchors:
        //block encodings from the ZkSpec block, the public-input count from the parsed circuit's npub_in, and
        //the rebased subfield boundary from the parsed circuit's subfield_boundary minus npub_in.
        Dictionary<string, string> oneAttribute = CircuitAnchor;
        LongfellowMdocZkSpec oneAttributeSpec = LongfellowMdocZkSpec.Version7OneAttribute;
        Assert.AreEqual(AnchorInt(oneAttribute, "zkspec_block_enc_hash"), oneAttributeSpec.HashBlockEncoded, "The one-attribute registry row's hash block encoding must match the anchor.");
        Assert.AreEqual(AnchorInt(oneAttribute, "zkspec_block_enc_sig"), oneAttributeSpec.SignatureBlockEncoded, "The one-attribute registry row's signature block encoding must match the anchor.");
        Assert.AreEqual(AnchorInt(oneAttribute, "hash_npub_in"), oneAttributeSpec.HashPublicInputCount, "The one-attribute registry row's public-input count must match the anchor.");
        Assert.AreEqual(AnchorInt(oneAttribute, "hash_subfield_boundary") - AnchorInt(oneAttribute, "hash_npub_in"), oneAttributeSpec.HashSubfieldBoundary, "The one-attribute registry row's rebased subfield boundary must match the anchor.");

        Dictionary<string, string> fourAttributes = FourAttributeCircuitAnchor;
        LongfellowMdocZkSpec fourAttributeSpec = LongfellowMdocZkSpec.Version7FourAttributes;
        Assert.AreEqual(AnchorInt(fourAttributes, "zkspec_block_enc_hash"), fourAttributeSpec.HashBlockEncoded, "The four-attribute registry row's hash block encoding must match the anchor.");
        Assert.AreEqual(AnchorInt(fourAttributes, "zkspec_block_enc_sig"), fourAttributeSpec.SignatureBlockEncoded, "The four-attribute registry row's signature block encoding must match the anchor.");
        Assert.AreEqual(AnchorInt(fourAttributes, "hash_npub_in"), fourAttributeSpec.HashPublicInputCount, "The four-attribute registry row's public-input count must match the anchor.");
        Assert.AreEqual(AnchorInt(fourAttributes, "hash_subfield_boundary") - AnchorInt(fourAttributes, "hash_npub_in"), fourAttributeSpec.HashSubfieldBoundary, "The four-attribute registry row's rebased subfield boundary must match the anchor.");

        //The proof-fixture template counts close the loop against the registry rows.
        Assert.AreEqual(oneAttributeSpec.HashTemplateElementCount, AnchorInt(CrownAnchor, "hash_template_count"), "The crown fixture's hash template count must match the one-attribute registry row.");
        Assert.AreEqual(fourAttributeSpec.HashTemplateElementCount, AnchorInt(FourAttributeProofAnchor, "hash_template_count"), "The four-attribute fixture's hash template count must match the four-attribute registry row.");
    }


    [TestMethod]
    public void TheSignatureCircuitIsSharedAcrossTheVersion7Bundles()
    {
        //The signature statement does not depend on the disclosed-attribute count, so the reference emits the
        //SAME signature circuit into every version-7 bundle; both anchors must agree on its structural id.
        Assert.AreEqual(PinnedSignatureCircuitId, CircuitAnchor["sig_id"], "The one-attribute bundle's signature circuit id must match the shared pin.");
        Assert.AreEqual(PinnedSignatureCircuitId, FourAttributeCircuitAnchor["sig_id"], "The four-attribute bundle's signature circuit id must match the shared pin.");
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
