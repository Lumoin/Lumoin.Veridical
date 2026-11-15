using Lumoin.Base;
using Lumoin.Veridical.Cli;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// In-process tests of <see cref="LongfellowJwtOperations"/>, the shared implementation behind the
/// <c>longfellow-jwt-prove</c> and <c>longfellow-jwt-verify</c> subcommands and their MCP tools. The
/// rejections here answer before any circuit is compiled.
/// </summary>
[TestClass]
internal sealed class LongfellowJwtOperationsTests
{
    private const string IssuerKeyX = "0x369b8ba929cf0f06be8272268f4091cfde4ef00fe35f1a25ff04e2d4293d692b";

    private const string IssuerKeyY = "0xbdf89d633ac7a622d73bee63bd00a68bcee5b3262054f4e767f7c25157182364";

    private const string Seed = "cli-jwt-operations";

    private const string KeyBindingWithoutSignature = "a.b.cc";


    private static IReadOnlyList<string> Attributes { get; } = ["given_name=Erika"];

    private static string[] ExpectedLines { get; } = ["a=1", "b=2"];


    [TestMethod]
    public void ProveRejectsAnAttributeWithoutASeparator()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtOperations.Prove("a.b.c~d.e.f", IssuerKeyX, IssuerKeyY, ["given_name"], 7, Seed, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void ProveRejectsAnUnsupportedBlockCapacity()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtOperations.Prove("a.b.c~d.e.f", IssuerKeyX, IssuerKeyY, Attributes, 8, Seed, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void ProveRejectsAnIssuerKeyCoordinateOfTheWrongLength()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtOperations.Prove("a.b.c~d.e.f", "0x1234", IssuerKeyY, Attributes, 7, Seed, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void ProveRejectsAnIssuerKeyCoordinateThatIsNotHex()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtOperations.Prove("a.b.c~d.e.f", "zz", IssuerKeyY, Attributes, 7, Seed, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void ProveRejectsAnEmptySeed()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtOperations.Prove("a.b.c~d.e.f", IssuerKeyX, IssuerKeyY, Attributes, 7, string.Empty, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void ProveRejectsATokenThatCannotSatisfyTheStatement()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtOperations.Prove("aaaa.bbbb.cccc~dddd.eeee.ffff", IssuerKeyX, IssuerKeyY, Attributes, 7, Seed, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void VerifyAnswersMalformedForAProofThatIsNotHex()
    {
        VerificationResult result = LongfellowJwtOperations.Verify("not-hex!", KeyBindingWithoutSignature, IssuerKeyX, IssuerKeyY, Attributes, 7, Seed, BaseMemoryPool.Shared);

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.IsFalse(result.IsValid);
    }


    [TestMethod]
    public void VerifyAnswersMalformedForAProofShorterThanTheMinimum()
    {
        VerificationResult result = LongfellowJwtOperations.Verify("00ff", KeyBindingWithoutSignature, IssuerKeyX, IssuerKeyY, Attributes, 7, Seed, BaseMemoryPool.Shared);

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
    }


    [TestMethod]
    public void VerifyAnswersMalformedForAKeyBindingWithoutAFixedWidthSignature()
    {
        string proof = string.Concat(Enumerable.Repeat("ab", 64));

        VerificationResult result = LongfellowJwtOperations.Verify(proof, "issuer.jws.sig~" + KeyBindingWithoutSignature, IssuerKeyX, IssuerKeyY, Attributes, 7, Seed, BaseMemoryPool.Shared);

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
        Assert.Contains("key-binding", result.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void VerifyAnswersMalformedForInvalidStatementArguments()
    {
        VerificationResult result = LongfellowJwtOperations.Verify("00", KeyBindingWithoutSignature, IssuerKeyX, IssuerKeyY, [], 7, Seed, BaseMemoryPool.Shared);

        Assert.AreEqual(VerificationStatus.Malformed, result.Status);
    }


    [TestMethod]
    public void SplitAttributeLinesDropsEmptyLinesAndTrimsEntries()
    {
        IReadOnlyList<string> lines = LongfellowJwtOperations.SplitAttributeLines("a=1\r\n\r\n  b=2  \n");

        Assert.AreSequenceEqual(ExpectedLines, lines.ToArray());
    }
}
