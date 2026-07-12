using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.DataIntegrity;
using Lumoin.Veridical.Hashing;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using VDS.RDF;
using VDS.RDF.Parsing;

namespace Lumoin.Veridical.Tests.DataIntegrity;

/// <summary>
/// End-to-end tests for the canonicalize-then-commit selective-disclosure flow:
/// an RDF credential is canonicalized (RDFC-1.0), committed through
/// <see cref="CanonicalGraphCommitment"/>, and a subset of its quads is disclosed
/// with membership proofs — each disclosed quad authenticates against the single
/// committed root while tampering is rejected.
/// </summary>
/// <remarks>
/// <para>
/// RDF canonicalization is the injected seam. Here it is wired to dotNetRDF's
/// <see cref="RdfCanonicalizer"/> (RDFC-1.0, SHA-256) — a real, external
/// canonicalizer standing in for the sibling data-integrity library until that is
/// consumable. The library under test holds no RDF shapes or algorithm; it commits
/// the opaque canonical quads. The blank node in the fixture makes canonicalization
/// do genuine deterministic blank-node labeling, so the isomorphism test exercises
/// the property, not just line sorting.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CanonicalGraphCommitmentTests
{
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int CredentialQuadCount = 5;

    //A product-passport-shaped credential in N-Quads, with the manufacturer as a
    //blank node so canonicalization must label it deterministically.
    private const string CredentialNQuads =
        "<https://example.com/products/battery-42> <https://example.com/vocab/manufacturer> _:mfr .\n" +
        "_:mfr <https://example.com/vocab/name> \"ACME Batteries\" .\n" +
        "_:mfr <https://example.com/vocab/country> <https://example.com/countries/fi> .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/recycledContent> \"35\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/carbonFootprint> \"12\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n";

    //The same graph, blank node relabeled and statements reordered: isomorphic, so
    //RDFC-1.0 canonicalizes it identically and it must commit to the same root.
    private const string IsomorphicCredentialNQuads =
        "<https://example.com/products/battery-42> <https://example.com/vocab/carbonFootprint> \"12\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n" +
        "_:org <https://example.com/vocab/country> <https://example.com/countries/fi> .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/recycledContent> \"35\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n" +
        "_:org <https://example.com/vocab/name> \"ACME Batteries\" .\n" +
        "<https://example.com/products/battery-42> <https://example.com/vocab/manufacturer> _:org .\n";


    private static MerkleHashDelegate Blake3TwoToOne { get; } = HashTwoToOne;

    //The injected canonicalizer: dotNetRDF's RDFC-1.0 implementation.
    private static RdfCanonicalizeDelegate Canonicalize { get; } = CanonicalizeWithRdfc;

    //Returns an empty quad set, to exercise the commitment's empty-graph guard
    //independently of the canonicalizer.
    private static RdfCanonicalizeDelegate EmptyCanonicalization { get; } = static _ => Array.Empty<ReadOnlyMemory<byte>>();

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
        CanonicalGraphCommitment commitment = Commit(CredentialNQuads);
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
        CanonicalGraphCommitment commitment = Commit(CredentialNQuads);

        //Disclose only the environmental claims; the manufacturer identity quads
        //are never revealed.
        int recycledIndex = IndexOfQuadContaining(commitment, "recycledContent");
        int carbonIndex = IndexOfQuadContaining(commitment, "carbonFootprint");

        foreach(int index in new[] { recycledIndex, carbonIndex })
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
        CanonicalGraphCommitment first = Commit(CredentialNQuads);
        CanonicalGraphCommitment second = Commit(IsomorphicCredentialNQuads);

        Assert.IsTrue(first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()),
            "An isomorphic graph (relabeled blank node, reordered statements) must commit to the same root.");
    }


    [TestMethod]
    public void AQuadPresentedAtTheWrongIndexIsRejected()
    {
        CanonicalGraphCommitment commitment = Commit(CredentialNQuads);
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
        CanonicalGraphCommitment commitment = Commit(CredentialNQuads);
        int index = IndexOfQuadContaining(commitment, "recycledContent");
        MerkleAuthenticationPath path = Track(commitment.ProveMembership(index, BaseMemoryPool.Shared));

        //Alter one byte of the committed canonical quad; its digest no longer
        //matches the committed leaf.
        byte[] tampered = commitment.GetQuad(index).ToArray();
        tampered[^3] ^= 0x01;

        bool authenticated = CanonicalGraphCommitment.VerifyMembership(
            commitment.Root, index, tampered, path, Blake3TwoToOne);

        Assert.IsFalse(authenticated, "A quad whose content differs from the committed one must not authenticate.");
    }


    [TestMethod]
    public void AForeignRootRejectsAMembershipProof()
    {
        CanonicalGraphCommitment commitment = Commit(CredentialNQuads);
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
        byte[] document = Encoding.UTF8.GetBytes(CredentialNQuads);
        Assert.ThrowsExactly<ArgumentException>(
            () => CanonicalGraphCommitment.Commit(document, EmptyCanonicalization, Blake3TwoToOne, BaseMemoryPool.Shared).Dispose());
    }


    private CanonicalGraphCommitment Commit(string nQuads)
    {
        byte[] document = Encoding.UTF8.GetBytes(nQuads);

        return Track(CanonicalGraphCommitment.Commit(document, Canonicalize, Blake3TwoToOne, BaseMemoryPool.Shared));
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


    //Injects dotNetRDF's RDFC-1.0 canonicalizer: parse the N-Quads dataset,
    //canonicalize, and return each canonical N-Quads line as opaque bytes.
    private static IReadOnlyList<ReadOnlyMemory<byte>> CanonicalizeWithRdfc(ReadOnlyMemory<byte> document)
    {
        string text = Encoding.UTF8.GetString(document.Span);
        using TripleStore store = new();
        new NQuadsParser().Load(store, new StringReader(text));

        RdfCanonicalizer.CanonicalizedRdfDataset canonical = new RdfCanonicalizer().Canonicalize(store);
        string[] lines = canonical.SerializedNQuads.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

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
