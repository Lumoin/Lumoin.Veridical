using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Memory;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The selective-disclosure primitive (<see cref="CborDisclosureGadgetExtensions"/>): proving a public,
/// approximately-CBOR attribute encoding (the text key <c>age_over_18</c> followed by the
/// boolean <c>true</c>) appears at a witnessed offset in a witnessed message. This is the
/// "locate the attribute in the signed bytes" half of the mdoc binding; the match is checked
/// with the prover-independent <see cref="LigeroConstraintEvaluator"/>.
/// </summary>
[TestClass]
internal sealed class CborDisclosureGadgetTests
{
    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private readonly List<LigeroConstraintSystemBuilder> builders = [];


    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in builders)
        {
            builder.Dispose();
        }
    }


    [TestMethod]
    public void DisclosesACborAttributeAtItsOffset()
    {
        byte[] attribute = CborTestEncoding.BooleanAttribute("age_over_18", true);
        byte[] prefix = [0xA1, 0x18, 0x2A];                       //a small CBOR-ish lead-in.
        byte[] suffix = [0x6A, .. "issued_at!!"u8.ToArray()];     //another element after it.
        byte[] message = [.. prefix, .. attribute, .. suffix];
        int offset = prefix.Length;

        //Present at its offset: satisfied.
        var present = NewBuilder();
        present.AssertContainsAt(present.WitnessMessage(message), offset, attribute);
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(present), "The attribute must be found at its offset.");

        //Same attribute, wrong offset: the bytes there differ, so the match fails.
        var shifted = NewBuilder();
        shifted.AssertContainsAt(shifted.WitnessMessage(message), offset + 1, attribute);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(shifted), "The attribute must not match one byte off.");

        //An attribute that is not in the message: rejected.
        byte[] absent = CborTestEncoding.BooleanAttribute("age_over_21", true);
        var missing = NewBuilder();
        missing.AssertContainsAt(missing.WitnessMessage(message), offset, absent);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(missing), "An absent attribute must not be disclosable.");
    }


    [TestMethod]
    public void DisclosesADerivedItemDigestInTheMso()
    {
        //The inner mdoc level: the signed MSO holds SHA-256(IssuerSignedItem). The item is
        //witnessed and hashed in-circuit, and its digest is matched as a substring of the MSO —
        //a derived (wire-valued) pattern, not a public one.
        byte[] item = "issuer-signed-item: age_over_18 = true"u8.ToArray();
        byte[] itemDigest = SHA256.HashData(item);
        byte[] prefix = [0xA1, 0x6C, .. "valueDigests"u8.ToArray()];
        byte[] suffix = [0xFF];
        byte[] mso = [.. prefix, .. itemDigest, .. suffix];
        int offset = prefix.Length;

        var present = NewBuilder();
        var presentSha = new Sha256Gadget(present);
        int[] presentDigest = presentSha.DigestByteWires(presentSha.Hash(present.WitnessMessage(item)));
        present.AssertContainsBytesAt(present.WitnessMessage(mso), offset, presentDigest);
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(present), "The MSO must contain SHA-256(item) at its offset.");

        //An MSO that holds a different item's digest must not match this item.
        byte[] otherMso = [.. prefix, .. SHA256.HashData("a different signed item"u8.ToArray()), .. suffix];
        var missing = NewBuilder();
        var missingSha = new Sha256Gadget(missing);
        int[] missingDigest = missingSha.DigestByteWires(missingSha.Hash(missing.WitnessMessage(item)));
        missing.AssertContainsBytesAt(missing.WitnessMessage(otherMso), offset, missingDigest);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(missing), "An MSO lacking the item's digest must be rejected.");
    }


    private LigeroConstraintSystemBuilder NewBuilder()
    {
        var builder = new LigeroConstraintSystemBuilder(
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);
        builders.Add(builder);

        return builder;
    }
}
