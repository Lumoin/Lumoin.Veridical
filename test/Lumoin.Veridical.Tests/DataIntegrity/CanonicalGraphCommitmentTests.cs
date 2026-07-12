using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.DataIntegrity;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace Lumoin.Veridical.Tests.DataIntegrity;

/// <summary>
/// End-to-end tests for the canonicalize-then-commit selective-disclosure flow:
/// a canonical RDF quad set is committed through <see cref="CanonicalGraphCommitment"/>,
/// a subset of quads is disclosed with membership proofs, and each disclosed quad
/// authenticates against the single committed root while tampering is rejected.
/// </summary>
/// <remarks>
/// <para>
/// The RDF canonicalization is the injected seam. Here it is exercised with a
/// fixture that is already a canonical N-Quads document, so the delegate only
/// splits it into its per-quad lines — no RDF parsing or canonicalization logic
/// lives in the library or the test. A production consumer wires a real RDFC-1.0
/// canonicalizer (the sibling data-integrity library, or an RDF toolkit) into the
/// same delegate; the crypto exercised here is unchanged by that swap.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CanonicalGraphCommitmentTests
{
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //A small fixture already in canonical N-Quads form: a product-passport-shaped
    //credential with a handful of statements. Each line is one canonical quad.
    private const string CanonicalCredential =
        "<https://example.com/products/battery-42> <https://example.com/vocab/manufacturer> <https://example.com/orgs/acme> .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/recycledContent> \"35\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/carbonFootprint> \"12\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/batchNumber> \"AC-2026-0042\" .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/originCountry> <https://example.com/countries/fi> .\n";

    private const int CredentialQuadCount = 5;


    private static MerkleHashDelegate Blake3TwoToOne { get; } = HashTwoToOne;

    //An injected canonicalizer stand-in: the fixture is already canonical, so the
    //delegate splits the document into its per-quad lines. Production wires a real
    //RDFC-1.0 canonicalizer into this same seam.
    private static RdfCanonicalizeDelegate SplitCanonicalNQuads { get; } = SplitLines;

    private List<IDisposable> Disposables { get; } = [];


    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    [TestMethod]
    public void EveryQuadOfTheCommittedGraphAuthenticatesAgainstTheRoot()
    {
        CanonicalGraphCommitment commitment = Commit(CanonicalCredential);
        Assert.AreEqual(CredentialQuadCount, commitment.QuadCount, "The five canonical quads must all be committed.");

        for(int i = 0; i < commitment.QuadCount; i++)
        {
            MerkleAuthenticationPath path = Track(commitment.ProveMembership(i, BaseMemoryPool.Shared));
            bool authenticated = CanonicalGraphCommitment.VerifyMembership(
                commitment.Root, i, commitment.GetQuad(i).Span, path, Blake3TwoToOne);

            Assert.IsTrue(authenticated, $"The quad at index {i} must authenticate against the committed root.");
        }
    }


    [TestMethod]
    public void ADisclosedSubsetVerifiesWhileTheRestStayHidden()
    {
        CanonicalGraphCommitment commitment = Commit(CanonicalCredential);

        //Disclose only the manufacturer and origin-country statements; the
        //recycled-content, carbon, and batch quads are never revealed.
        int manufacturerIndex = IndexOfQuadContaining(commitment, "manufacturer");
        int originIndex = IndexOfQuadContaining(commitment, "originCountry");

        foreach(int index in new[] { manufacturerIndex, originIndex })
        {
            MerkleAuthenticationPath path = Track(commitment.ProveMembership(index, BaseMemoryPool.Shared));
            bool authenticated = CanonicalGraphCommitment.VerifyMembership(
                commitment.Root, index, commitment.GetQuad(index).Span, path, Blake3TwoToOne);

            Assert.IsTrue(authenticated, $"The disclosed quad at index {index} must authenticate against the root.");
        }
    }


    [TestMethod]
    public void IsomorphicInputCommitsToTheSameRoot()
    {
        //The same statements in a different document order must yield the same
        //root: the commitment orders the set by content digest.
        string reordered = ReverseLines(CanonicalCredential);

        CanonicalGraphCommitment first = Commit(CanonicalCredential);
        CanonicalGraphCommitment second = Commit(reordered);

        Assert.IsTrue(first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()),
            "The same quad set in a different order must commit to the same root.");
    }


    [TestMethod]
    public void AQuadPresentedAtTheWrongIndexIsRejected()
    {
        CanonicalGraphCommitment commitment = Commit(CanonicalCredential);
        int index = 0;
        int otherIndex = commitment.QuadCount - 1;
        MerkleAuthenticationPath path = Track(commitment.ProveMembership(index, BaseMemoryPool.Shared));

        //The genuine quad and path for index 0, verified as if it were the last
        //quad, must fail: the path authenticates only its own position.
        bool authenticated = CanonicalGraphCommitment.VerifyMembership(
            commitment.Root, otherIndex, commitment.GetQuad(index).Span, path, Blake3TwoToOne);

        Assert.IsFalse(authenticated, "A quad's membership proof must not authenticate at a different index.");
    }


    [TestMethod]
    public void ATamperedQuadIsRejected()
    {
        CanonicalGraphCommitment commitment = Commit(CanonicalCredential);
        int index = IndexOfQuadContaining(commitment, "recycledContent");
        MerkleAuthenticationPath path = Track(commitment.ProveMembership(index, BaseMemoryPool.Shared));

        //Claim a different value for the disclosed quad than the committed one.
        byte[] tampered = Encoding.UTF8.GetBytes(
            "<https://example.com/products/battery-42> <https://example.com/vocab/recycledContent> \"95\"^^<http://www.w3.org/2001/XMLSchema#integer> .");

        bool authenticated = CanonicalGraphCommitment.VerifyMembership(
            commitment.Root, index, tampered, path, Blake3TwoToOne);

        Assert.IsFalse(authenticated, "A quad whose content differs from the committed one must not authenticate.");
    }


    [TestMethod]
    public void AForeignRootRejectsAMembershipProof()
    {
        CanonicalGraphCommitment commitment = Commit(CanonicalCredential);
        MerkleAuthenticationPath path = Track(commitment.ProveMembership(0, BaseMemoryPool.Shared));

        Span<byte> tamperedRootBytes = stackalloc byte[DigestSizeBytes];
        commitment.Root.AsReadOnlySpan().CopyTo(tamperedRootBytes);
        tamperedRootBytes[0] ^= 0x01;
        MerkleRoot foreignRoot = Track(MerkleRoot.FromBytes(tamperedRootBytes, BaseMemoryPool.Shared));

        bool authenticated = CanonicalGraphCommitment.VerifyMembership(
            foreignRoot, 0, commitment.GetQuad(0).Span, path, Blake3TwoToOne);

        Assert.IsFalse(authenticated, "A membership proof must not authenticate against a foreign root.");
    }


    [TestMethod]
    public void CommittingAnEmptyGraphIsRejected()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Commit(string.Empty).Dispose());
    }


    private CanonicalGraphCommitment Commit(string canonicalNQuads)
    {
        byte[] document = Encoding.UTF8.GetBytes(canonicalNQuads);

        return Track(CanonicalGraphCommitment.Commit(document, SplitCanonicalNQuads, Blake3TwoToOne, BaseMemoryPool.Shared));
    }


    private static int IndexOfQuadContaining(CanonicalGraphCommitment commitment, string predicateFragment)
    {
        for(int i = 0; i < commitment.QuadCount; i++)
        {
            if(Encoding.UTF8.GetString(commitment.GetQuad(i).Span).Contains(predicateFragment, StringComparison.Ordinal))
            {
                return i;
            }
        }

        throw new InvalidOperationException($"No committed quad contains '{predicateFragment}'.");
    }


    private static string ReverseLines(string document)
    {
        string[] lines = document.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Array.Reverse(lines);

        return string.Join('\n', lines) + '\n';
    }


    private static IReadOnlyList<ReadOnlyMemory<byte>> SplitLines(ReadOnlyMemory<byte> document)
    {
        string text = Encoding.UTF8.GetString(document.Span);
        string[] lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var quads = new List<ReadOnlyMemory<byte>>(lines.Length);
        foreach(string line in lines)
        {
            quads.Add(Encoding.UTF8.GetBytes(line));
        }

        return quads;
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private T Track<T>(T disposable) where T : IDisposable
    {
        Disposables.Add(disposable);

        return disposable;
    }
}
