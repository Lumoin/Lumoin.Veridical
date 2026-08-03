using Lumoin.Veridical.Longfellow;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The validation matrix of the JWT statement facade's public support types:
/// <see cref="LongfellowJwtAttribute"/>'s capacity and UTF-8 encoding contracts,
/// <see cref="LongfellowJwtStatement"/>'s coordinate-length and attribute-list contracts (including its
/// faithful acceptance of duplicate attribute identifiers), <see cref="LongfellowJwtZkSpec"/>'s pinned
/// block-capacity registry, <see cref="LongfellowJwtProof"/>'s envelope contract,
/// <see cref="LongfellowJwtCryptoSuite"/>'s required-delegate contract, and <see cref="LongfellowJwt"/>'s
/// null-argument contracts on <see cref="LongfellowJwt.Prove"/> and <see cref="LongfellowJwt.Verify"/> —
/// every construction contract pinned.
/// </summary>
[TestClass]
internal sealed class LongfellowJwtValidationTests
{
    /// <summary>A two-byte UTF-8 character (Latin small letter a with diaeresis) that pins <see cref="LongfellowJwtAttribute.FromStrings"/>'s UTF-8 encoding.</summary>
    private const string TwoByteUtf8Character = "ä";

    /// <summary>The UTF-8 byte count of <see cref="TwoByteUtf8Character"/>.</summary>
    private const int TwoByteUtf8ByteCount = 2;


    /// <summary>
    /// Pins <see cref="LongfellowJwtAttribute.Create"/>'s exact capacity boundary for the identifier and
    /// the value, its acceptance of empty sides, <see cref="LongfellowJwtAttribute.FromStrings"/>'s null
    /// rejection, and its UTF-8 encoding of a multi-byte character.
    /// </summary>
    [TestMethod]
    public void AttributeCapacityBoundariesAndFromStringsContractsHold()
    {
        Span<byte> idAtCapacity = stackalloc byte[LongfellowJwtAttribute.MaxIdBytes];
        Span<byte> valueAtCapacity = stackalloc byte[LongfellowJwtAttribute.MaxValueBytes];
        LongfellowJwtAttribute atCapacity = LongfellowJwtAttribute.Create(idAtCapacity.ToArray(), valueAtCapacity.ToArray());
        Assert.HasCount(LongfellowJwtAttribute.MaxIdBytes, atCapacity.Id, "An identifier at exactly the capacity must be accepted.");
        Assert.HasCount(LongfellowJwtAttribute.MaxValueBytes, atCapacity.Value, "A value at exactly the capacity must be accepted.");

        LongfellowJwtAttribute empty = LongfellowJwtAttribute.Create(ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty);
        Assert.HasCount(0, empty.Id, "An empty identifier must be accepted.");
        Assert.HasCount(0, empty.Value, "An empty value must be accepted.");

        Assert.ThrowsExactly<ArgumentException>(() => CreateAttributeWithIdOneByteOverCapacity(), "An identifier one byte over the capacity must reject.");
        Assert.ThrowsExactly<ArgumentException>(() => CreateAttributeWithValueOneByteOverCapacity(), "A value one byte over the capacity must reject.");

        Assert.ThrowsExactly<ArgumentNullException>(() => LongfellowJwtAttribute.FromStrings(null!, "value"), "A null identifier must reject.");
        Assert.ThrowsExactly<ArgumentNullException>(() => LongfellowJwtAttribute.FromStrings("id", null!), "A null value must reject.");

        LongfellowJwtAttribute utf8Attribute = LongfellowJwtAttribute.FromStrings("id", TwoByteUtf8Character);
        Assert.HasCount(TwoByteUtf8ByteCount, utf8Attribute.Value, "A two-byte UTF-8 character must encode to exactly two bytes.");
    }


    /// <summary>Pins <see cref="LongfellowJwtStatement.Create"/>'s exact 32-byte coordinate-length contract for both the X and the Y sides.</summary>
    [TestMethod]
    public void StatementCreateEnforcesTheExactCoordinateLengthContract()
    {
        Assert.ThrowsExactly<ArgumentException>(() => CreateStatementWithXCoordinateOneByteShort(), "A 31-byte X coordinate must reject.");
        Assert.ThrowsExactly<ArgumentException>(() => CreateStatementWithXCoordinateOneByteOver(), "A 33-byte X coordinate must reject.");
        Assert.ThrowsExactly<ArgumentException>(() => CreateStatementWithYCoordinateOneByteShort(), "A 31-byte Y coordinate must reject.");
        Assert.ThrowsExactly<ArgumentException>(() => CreateStatementWithYCoordinateOneByteOver(), "A 33-byte Y coordinate must reject.");

        Span<byte> validX = stackalloc byte[ScalarSize];
        Span<byte> validY = stackalloc byte[ScalarSize];
        LongfellowJwtStatement statement = LongfellowJwtStatement.Create(
            validX.ToArray(), validY.ToArray(), [LongfellowJwtAttribute.FromStrings("id", "value")], LongfellowJwtZkSpec.SevenBlocks);
        Assert.HasCount(ScalarSize, statement.IssuerKeyX, "An exactly 32-byte X coordinate must be accepted.");
        Assert.HasCount(ScalarSize, statement.IssuerKeyY, "An exactly 32-byte Y coordinate must be accepted.");
    }


    /// <summary>
    /// Pins <see cref="LongfellowJwtStatement.Create"/>'s attribute-list contract: null and empty rejection,
    /// a null list entry rejection, and its faithful acceptance of two attributes sharing the same
    /// identifier — duplicates are independent patterns, not merged.
    /// </summary>
    [TestMethod]
    public void StatementAttributeListContractHoldsAndAllowsDuplicateIdentifiers()
    {
        Span<byte> x = stackalloc byte[ScalarSize];
        Span<byte> y = stackalloc byte[ScalarSize];
        byte[] xBytes = x.ToArray();
        byte[] yBytes = y.ToArray();

        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwtStatement.Create(xBytes, yBytes, null!, LongfellowJwtZkSpec.SevenBlocks),
            "A null attribute list must reject.");
        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwtStatement.Create(xBytes, yBytes, [LongfellowJwtAttribute.FromStrings("id", "value")], null!),
            "A null spec must reject.");
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtStatement.Create(xBytes, yBytes, [], LongfellowJwtZkSpec.SevenBlocks),
            "An empty attribute list must reject.");
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwtStatement.Create(xBytes, yBytes, [null!], LongfellowJwtZkSpec.SevenBlocks),
            "A list entry that is null must reject.");

        LongfellowJwtAttribute first = LongfellowJwtAttribute.FromStrings("given_name", "Erika");
        LongfellowJwtAttribute second = LongfellowJwtAttribute.FromStrings("given_name", "Richer");
        LongfellowJwtStatement statement = LongfellowJwtStatement.Create(xBytes, yBytes, [first, second], LongfellowJwtZkSpec.SevenBlocks);
        Assert.HasCount(2, statement.Attributes, "Two attributes sharing an identifier are independent patterns and both must be retained.");
        Assert.AreSame(first, statement.Attributes[0], "The first duplicate-identifier attribute must be retained in place.");
        Assert.AreSame(second, statement.Attributes[1], "The second duplicate-identifier attribute must be retained in place.");
    }


    /// <summary>Pins the closed spec registry's block capacities and their derived maximum message bytes (block capacity times 64 minus the mandatory pad and bit-length tail).</summary>
    [TestMethod]
    public void ZkSpecRegistryPinsTheBlockCapacityAndMaximumMessageBytes()
    {
        const int SevenBlockCapacity = 7;
        const int NineBlockCapacity = 9;
        const int SevenBlockMaximumMessageBytes = 439;
        const int NineBlockMaximumMessageBytes = 567;

        Assert.AreEqual(SevenBlockCapacity, LongfellowJwtZkSpec.SevenBlocks.BlockCapacity, "The seven-block spec must report a block capacity of seven.");
        Assert.AreEqual(NineBlockCapacity, LongfellowJwtZkSpec.NineBlocks.BlockCapacity, "The nine-block spec must report a block capacity of nine.");
        Assert.AreEqual(SevenBlockMaximumMessageBytes, LongfellowJwtZkSpec.SevenBlocks.MaximumMessageBytes, "The seven-block spec's maximum message bytes is its block capacity times 64 minus 9.");
        Assert.AreEqual(NineBlockMaximumMessageBytes, LongfellowJwtZkSpec.NineBlocks.MaximumMessageBytes, "The nine-block spec's maximum message bytes is its block capacity times 64 minus 9.");
    }


    /// <summary>Pins <see cref="LongfellowJwtProof.FromCanonical"/>'s null-pool and minimum-size contracts, and that a valid envelope round-trips its exact bytes.</summary>
    [TestMethod]
    public void ProofFromCanonicalEnforcesTheEnvelopeContractAndRoundTripsTheBytes()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CreateProofWithNullPool(), "A null pool must reject.");
        Assert.ThrowsExactly<ArgumentException>(() => CreateProofWithEnvelopeOneByteShortOfMinimum(), "An envelope one byte short of the minimum must reject.");

        Span<byte> envelopeBytes = stackalloc byte[LongfellowJwtProof.MinimumSizeBytes];
        for(int i = 0; i < envelopeBytes.Length; i++)
        {
            envelopeBytes[i] = (byte)i;
        }

        using LongfellowJwtProof proof = LongfellowJwtProof.FromCanonical(envelopeBytes, BaseMemoryPool.Shared);
        Assert.AreSequenceEqual(envelopeBytes.ToArray(), proof.AsReadOnlySpan().ToArray(), "The proof must round-trip the exact canonical bytes.");
    }


    /// <summary>Pins <see cref="LongfellowJwtCryptoSuite.Create"/>'s requirement that every primitive delegate is non-null, one position at a time, and that <see cref="LongfellowJwtCryptoSuite.Default"/> supplies every primitive.</summary>
    [TestMethod]
    public void CryptoSuiteCreateRequiresEveryDelegateAndDefaultIsFullyPopulated()
    {
        LongfellowJwtCryptoSuite defaultSuite = LongfellowJwtCryptoSuite.Default;

        Assert.ThrowsExactly<ArgumentNullException>(() => LongfellowJwtCryptoSuite.Create(
            null!, defaultSuite.LeafHash, defaultSuite.IncrementalHashFactory, defaultSuite.BlockCipher, defaultSuite.ProverRandom),
            "A null Merkle hash must reject.");
        Assert.ThrowsExactly<ArgumentNullException>(() => LongfellowJwtCryptoSuite.Create(
            defaultSuite.MerkleHash, null!, defaultSuite.IncrementalHashFactory, defaultSuite.BlockCipher, defaultSuite.ProverRandom),
            "A null leaf hash must reject.");
        Assert.ThrowsExactly<ArgumentNullException>(() => LongfellowJwtCryptoSuite.Create(
            defaultSuite.MerkleHash, defaultSuite.LeafHash, null!, defaultSuite.BlockCipher, defaultSuite.ProverRandom),
            "A null incremental hash factory must reject.");
        Assert.ThrowsExactly<ArgumentNullException>(() => LongfellowJwtCryptoSuite.Create(
            defaultSuite.MerkleHash, defaultSuite.LeafHash, defaultSuite.IncrementalHashFactory, null!, defaultSuite.ProverRandom),
            "A null block cipher must reject.");
        Assert.ThrowsExactly<ArgumentNullException>(() => LongfellowJwtCryptoSuite.Create(
            defaultSuite.MerkleHash, defaultSuite.LeafHash, defaultSuite.IncrementalHashFactory, defaultSuite.BlockCipher, null!),
            "A null prover-random source must reject.");

        Assert.IsNotNull(defaultSuite.MerkleHash, "The default suite must supply a Merkle hash.");
        Assert.IsNotNull(defaultSuite.LeafHash, "The default suite must supply a leaf hash.");
        Assert.IsNotNull(defaultSuite.IncrementalHashFactory, "The default suite must supply an incremental hash factory.");
        Assert.IsNotNull(defaultSuite.BlockCipher, "The default suite must supply a block cipher.");
        Assert.IsNotNull(defaultSuite.ProverRandom, "The default suite must supply a prover-random source.");
    }


    /// <summary>
    /// Pins that <see cref="LongfellowJwt.Prove"/> rejects a null statement and a null pool, and that
    /// <see cref="LongfellowJwt.Verify"/> rejects a null proof, a null statement, and a null pool — every
    /// null check answers before any witness computation or circuit compilation.
    /// </summary>
    [TestMethod]
    public void FacadeProveAndVerifyRejectNullArgumentsBeforeAnyWork()
    {
        byte[] placeholderBytes = Encoding.ASCII.GetBytes("a.b.c~d.e.f");
        byte[] transcriptSeed = Encoding.ASCII.GetBytes("facade-null-contract-seed");

        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwt.Prove(placeholderBytes, null!, transcriptSeed, BaseMemoryPool.Shared),
            "A null statement must reject before any witness or circuit work.");
        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwt.Prove(placeholderBytes, NewPlaceholderStatement(), transcriptSeed, null!),
            "A null pool must reject before any witness or circuit work.");

        Span<byte> zeroEnvelope = stackalloc byte[LongfellowJwtProof.MinimumSizeBytes];
        using LongfellowJwtProof proof = LongfellowJwtProof.FromCanonical(zeroEnvelope, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwt.Verify(null!, placeholderBytes, NewPlaceholderStatement(), transcriptSeed, BaseMemoryPool.Shared),
            "A null proof must reject before any work.");
        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwt.Verify(proof, placeholderBytes, null!, transcriptSeed, BaseMemoryPool.Shared),
            "A null statement must reject before any work.");
        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwt.Verify(proof, placeholderBytes, NewPlaceholderStatement(), transcriptSeed, null!),
            "A null pool must reject before any work.");
    }


    /// <summary>Builds a minimally valid statement for the facade's null-argument gates, whose coordinate and attribute content is irrelevant since the null checks precede all use of it.</summary>
    /// <returns>The statement.</returns>
    private static LongfellowJwtStatement NewPlaceholderStatement()
    {
        Span<byte> x = stackalloc byte[ScalarSize];
        Span<byte> y = stackalloc byte[ScalarSize];

        return LongfellowJwtStatement.Create(x.ToArray(), y.ToArray(), [LongfellowJwtAttribute.FromStrings("id", "value")], LongfellowJwtZkSpec.SevenBlocks);
    }


    /// <summary>Calls <see cref="LongfellowJwtAttribute.Create"/> with an identifier one byte over <see cref="LongfellowJwtAttribute.MaxIdBytes"/>.</summary>
    private static void CreateAttributeWithIdOneByteOverCapacity()
    {
        Span<byte> overId = stackalloc byte[LongfellowJwtAttribute.MaxIdBytes + 1];
        Span<byte> value = stackalloc byte[LongfellowJwtAttribute.MaxValueBytes];
        LongfellowJwtAttribute.Create(overId.ToArray(), value.ToArray());
    }


    /// <summary>Calls <see cref="LongfellowJwtAttribute.Create"/> with a value one byte over <see cref="LongfellowJwtAttribute.MaxValueBytes"/>.</summary>
    private static void CreateAttributeWithValueOneByteOverCapacity()
    {
        Span<byte> id = stackalloc byte[LongfellowJwtAttribute.MaxIdBytes];
        Span<byte> overValue = stackalloc byte[LongfellowJwtAttribute.MaxValueBytes + 1];
        LongfellowJwtAttribute.Create(id.ToArray(), overValue.ToArray());
    }


    /// <summary>Calls <see cref="LongfellowJwtStatement.Create"/> with a 31-byte X coordinate.</summary>
    private static void CreateStatementWithXCoordinateOneByteShort()
    {
        Span<byte> shortX = stackalloc byte[ScalarSize - 1];
        Span<byte> validY = stackalloc byte[ScalarSize];
        LongfellowJwtStatement.Create(shortX.ToArray(), validY.ToArray(), [LongfellowJwtAttribute.FromStrings("id", "value")], LongfellowJwtZkSpec.SevenBlocks);
    }


    /// <summary>Calls <see cref="LongfellowJwtStatement.Create"/> with a 33-byte X coordinate.</summary>
    private static void CreateStatementWithXCoordinateOneByteOver()
    {
        Span<byte> longX = stackalloc byte[ScalarSize + 1];
        Span<byte> validY = stackalloc byte[ScalarSize];
        LongfellowJwtStatement.Create(longX.ToArray(), validY.ToArray(), [LongfellowJwtAttribute.FromStrings("id", "value")], LongfellowJwtZkSpec.SevenBlocks);
    }


    /// <summary>Calls <see cref="LongfellowJwtStatement.Create"/> with a 31-byte Y coordinate.</summary>
    private static void CreateStatementWithYCoordinateOneByteShort()
    {
        Span<byte> validX = stackalloc byte[ScalarSize];
        Span<byte> shortY = stackalloc byte[ScalarSize - 1];
        LongfellowJwtStatement.Create(validX.ToArray(), shortY.ToArray(), [LongfellowJwtAttribute.FromStrings("id", "value")], LongfellowJwtZkSpec.SevenBlocks);
    }


    /// <summary>Calls <see cref="LongfellowJwtStatement.Create"/> with a 33-byte Y coordinate.</summary>
    private static void CreateStatementWithYCoordinateOneByteOver()
    {
        Span<byte> validX = stackalloc byte[ScalarSize];
        Span<byte> longY = stackalloc byte[ScalarSize + 1];
        LongfellowJwtStatement.Create(validX.ToArray(), longY.ToArray(), [LongfellowJwtAttribute.FromStrings("id", "value")], LongfellowJwtZkSpec.SevenBlocks);
    }


    /// <summary>Calls <see cref="LongfellowJwtProof.FromCanonical"/> with a null pool.</summary>
    private static void CreateProofWithNullPool()
    {
        Span<byte> envelope = stackalloc byte[LongfellowJwtProof.MinimumSizeBytes];
        LongfellowJwtProof.FromCanonical(envelope, null!);
    }


    /// <summary>Calls <see cref="LongfellowJwtProof.FromCanonical"/> with an envelope one byte short of <see cref="LongfellowJwtProof.MinimumSizeBytes"/>.</summary>
    private static void CreateProofWithEnvelopeOneByteShortOfMinimum()
    {
        Span<byte> tooShort = stackalloc byte[LongfellowJwtProof.MinimumSizeBytes - 1];
        LongfellowJwtProof.FromCanonical(tooShort, BaseMemoryPool.Shared).Dispose();
    }
}
