using Lumoin.Veridical.Longfellow;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// Pins the Longfellow conformance fixtures' identity: the ZkSpec registry identity and the raw-stream
/// digest recorded in the circuit-import anchor are asserted here against the documented pinned values,
/// so a fixture regeneration that drifts from the documented pin fails the default suite rather than
/// drifting silently. See the "Longfellow upstream pin" section of <c>SECURITY.md</c> for the full
/// identity chain and the re-pin tripwires.
/// </summary>
[TestClass]
internal sealed class LongfellowUpstreamPinTests
{
    /// <summary>Relative path to the one-attribute circuit-import anchor.</summary>
    private const string AnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-output.txt";

    /// <summary>Relative path to the one-attribute proof anchor.</summary>
    private const string CrownAnchorRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";

    /// <summary>Relative path to the four-attribute circuit-import anchor.</summary>
    private const string FourAttributeAnchorRelativePath = "TestMaterial/Longfellow/mdoc-circuit-anchor-4attr-output.txt";

    /// <summary>Relative path to the four-attribute proof anchor.</summary>
    private const string FourAttributeProofAnchorRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-4attr-output.txt";

    /// <summary>The pinned ZkSpec system identifier for every version-7 bundle.</summary>
    private const string PinnedZkSpecSystem = "longfellow-libzk-v1";

    /// <summary>The pinned ZkSpec version for every version-7 bundle.</summary>
    private const int PinnedZkSpecVersion = 7;

    /// <summary>The pinned disclosed-attribute count for the one-attribute bundle.</summary>
    private const int PinnedZkSpecAttributeCount = 1;

    /// <summary>The pinned hash circuit Reed-Solomon block-encoding length for the one-attribute bundle.</summary>
    private const int PinnedBlockEncodedHash = 4151;

    /// <summary>The pinned signature circuit Reed-Solomon block-encoding length, shared by every version-7 bundle.</summary>
    private const int PinnedBlockEncodedSignature = 4096;

    /// <summary>The pinned hash of the one-attribute bundle's canonical circuit encoding.</summary>
    private const string PinnedCanonicalCircuitHash = "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121";

    /// <summary>The pinned SHA-256 digest of the one-attribute bundle's decompressed raw circuit stream.</summary>
    private const string PinnedRawCircuitSha256 = "332e3a96826a5f1a7a745dc9acac82e4a38051ee435877f95cdba71493354835";

    /// <summary>The pinned proof-specification version, carried by both the one-attribute and four-attribute proof fixtures.</summary>
    private const int PinnedProofSpecVersion = 7;

    /// <summary>The pinned disclosed-attribute count for the four-attribute bundle.</summary>
    private const int PinnedFourAttributeCount = 4;

    /// <summary>The pinned hash circuit Reed-Solomon block-encoding length for the four-attribute bundle.</summary>
    private const int PinnedFourAttributeBlockEncodedHash = 4415;

    /// <summary>The pinned hash of the four-attribute bundle's canonical circuit encoding.</summary>
    private const string PinnedFourAttributeCanonicalCircuitHash = "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460";

    /// <summary>The pinned SHA-256 digest of the four-attribute bundle's decompressed raw circuit stream.</summary>
    private const string PinnedFourAttributeRawCircuitSha256 = "5a282c3f77d35a32ec5af028ece8c2c8cab612f4aa1d178f7607984dd5787010";

    /// <summary>The pinned structural id of the signature circuit, shared by every version-7 attribute count; both circuit anchors must agree on it.</summary>
    private const string PinnedSignatureCircuitId = "2845210af05740e6e3e054762f9e35ff5fc4fb23088716e369f7cf73eb61df2d";

    /// <summary>
    /// The one-attribute circuit-import anchor's key-value pairs, parsed once and shared across
    /// the pin tests below.
    /// </summary>
    private static Dictionary<string, string> CircuitAnchor { get; } = LoadAnchors(AnchorRelativePath);

    /// <summary>
    /// The one-attribute proof anchor's key-value pairs, parsed once and shared across the pin
    /// tests below (the proof anchor carries the full envelope hex, so re-parsing per test is
    /// avoidable weight).
    /// </summary>
    private static Dictionary<string, string> CrownAnchor { get; } = LoadAnchors(CrownAnchorRelativePath);

    /// <summary>
    /// The four-attribute circuit-import anchor's key-value pairs, parsed once and shared across
    /// the pin tests below.
    /// </summary>
    private static Dictionary<string, string> FourAttributeCircuitAnchor { get; } = LoadAnchors(FourAttributeAnchorRelativePath);

    /// <summary>
    /// The four-attribute proof anchor's key-value pairs, parsed once and shared across the pin
    /// tests below (the proof anchor carries the full envelope hex, so re-parsing per test is
    /// avoidable weight).
    /// </summary>
    private static Dictionary<string, string> FourAttributeProofAnchor { get; } = LoadAnchors(FourAttributeProofAnchorRelativePath);


    /// <summary>The one-attribute circuit-import anchor's ZkSpec identity matches the pinned values.</summary>
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


    /// <summary>The one-attribute circuit-import anchor's decompressed raw circuit stream digest matches the pinned value.</summary>
    [TestMethod]
    public void TheCircuitAnchorPinsTheDocumentedRawStreamDigest()
    {
        Dictionary<string, string> anchor = CircuitAnchor;

        Assert.AreEqual(PinnedRawCircuitSha256, anchor["raw_rawsha"], "The decompressed raw circuit stream digest must match the documented upstream pin.");
    }


    /// <summary>The one-attribute proof fixture carries the pinned ZkSpec version.</summary>
    [TestMethod]
    public void TheCrownProofFixtureCarriesThePinnedSpecVersion()
    {
        Dictionary<string, string> anchor = CrownAnchor;

        Assert.AreEqual(PinnedProofSpecVersion, AnchorInt(anchor, "version"), "The crown proof fixture's ZkSpec version must match the documented upstream pin.");
    }


    /// <summary>The four-attribute circuit-import anchor's ZkSpec identity matches the pinned values.</summary>
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


    /// <summary>The four-attribute circuit-import anchor's decompressed raw circuit stream digest matches the pinned value.</summary>
    [TestMethod]
    public void TheFourAttributeCircuitAnchorPinsTheDocumentedRawStreamDigest()
    {
        Dictionary<string, string> anchor = FourAttributeCircuitAnchor;

        Assert.AreEqual(PinnedFourAttributeRawCircuitSha256, anchor["raw_rawsha"], "The decompressed four-attribute raw circuit stream digest must match the documented upstream pin.");
    }


    /// <summary>The four-attribute proof fixture carries the pinned ZkSpec version and attribute count.</summary>
    [TestMethod]
    public void TheFourAttributeProofFixtureCarriesThePinnedSpecIdentity()
    {
        Dictionary<string, string> anchor = FourAttributeProofAnchor;

        Assert.AreEqual(PinnedProofSpecVersion, AnchorInt(anchor, "version"), "The four-attribute proof fixture's ZkSpec version must match the documented upstream pin.");
        Assert.AreEqual(PinnedFourAttributeCount, AnchorInt(anchor, "num_attributes"), "The four-attribute proof fixture's attribute count must match the documented upstream pin.");
    }


    /// <summary>
    /// The public <see cref="LongfellowMdocZkSpec"/> registry rows match the reference anchors'
    /// block encodings, public-input counts, and rebased subfield boundaries, for both the
    /// one-attribute and four-attribute bundles.
    /// </summary>
    [TestMethod]
    public void TheSpecRegistryRowsMatchTheReferenceAnchors()
    {
        //The public LongfellowMdocZkSpec rows are the values the facade proves and verifies with; each row
        //is asserted against the reference anchor of its bundle so the registry cannot drift from the anchors:
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


    /// <summary>The signature circuit's structural id is the same across both the one-attribute and four-attribute version-7 anchors.</summary>
    [TestMethod]
    public void TheSignatureCircuitIsSharedAcrossTheVersion7Bundles()
    {
        //The signature statement does not depend on the disclosed-attribute count, so the reference emits the
        //SAME signature circuit into every version-7 bundle; both anchors must agree on its structural id.
        Assert.AreEqual(PinnedSignatureCircuitId, CircuitAnchor["sig_id"], "The one-attribute bundle's signature circuit id must match the shared pin.");
        Assert.AreEqual(PinnedSignatureCircuitId, FourAttributeCircuitAnchor["sig_id"], "The four-attribute bundle's signature circuit id must match the shared pin.");
    }


    /// <summary>Parses the value at <paramref name="key"/> in <paramref name="anchor"/> as a base-10 integer.</summary>
    private static int AnchorInt(Dictionary<string, string> anchor, string key) => int.Parse(anchor[key], CultureInfo.InvariantCulture);


    /// <summary>Reads the key=value pairs from the anchor file at <paramref name="relativePath"/> into a map.</summary>
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
