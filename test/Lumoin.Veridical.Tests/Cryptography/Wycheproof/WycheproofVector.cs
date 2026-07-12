using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Cryptography.Wycheproof;

/// <summary>
/// A single flattened Wycheproof ECDSA test vector, ready for a harness runner. The
/// <see cref="CompressedKey"/> field holds the 33-byte SEC1-compressed public key
/// parsed from the group that owns this vector.
/// </summary>
internal sealed record WycheproofVector(
    int TcId,
    string Comment,
    string[] Flags,
    byte[] Message,
    byte[] Signature,
    bool ExpectedValid,
    byte[] CompressedKey);


/// <summary>
/// The deserialized result of one Wycheproof fixture file: the declared
/// <see cref="DeclaredNumberOfTests"/> from the JSON header and the flat
/// <see cref="Vectors"/> list produced by parsing every group.
/// </summary>
internal sealed class WycheproofFileResult
{
    public WycheproofFileResult(int declaredNumberOfTests, IReadOnlyList<WycheproofVector> vectors)
    {
        DeclaredNumberOfTests = declaredNumberOfTests;
        Vectors = vectors;
    }


    /// <summary>The <c>numberOfTests</c> field declared in the fixture JSON header.</summary>
    public int DeclaredNumberOfTests { get; }

    /// <summary>All vectors from all test groups, flattened.</summary>
    public IReadOnlyList<WycheproofVector> Vectors { get; }
}
