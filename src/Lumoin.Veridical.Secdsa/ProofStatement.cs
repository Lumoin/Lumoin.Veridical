using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The statement a transferable proof is about, as a layout profile sees it when it encodes a structure: the
/// generators <c>Gᵢ</c>, the public keys <c>Dᵢ</c> and the additional authenticated data <c>AAD</c> (Verheul
/// Statement (9), Algorithms 22 to 24). It references its components and does not own them: whoever created the
/// generators, public keys and data disposes them.
/// </summary>
/// <remarks>
/// Everything in a statement is public. The type exists so that an encoder has one parameter for the
/// statement and the algorithms never decide how its fields are laid out.
/// </remarks>
public sealed class ProofStatement
{
    /// <summary>The generators <c>G₀, …, Gₙ</c>.</summary>
    public P256PointVector Generators { get; }

    /// <summary>The public keys <c>D₀, …, Dₙ</c>, where <c>Dᵢ = d·Gᵢ</c> when the statement holds.</summary>
    public P256PointVector PublicKeys { get; }

    /// <summary>The additional authenticated data <c>AAD</c>.</summary>
    public AdditionalData AdditionalAuthenticatedData { get; }


    /// <summary>Creates a statement.</summary>
    /// <param name="generators">The generators.</param>
    /// <param name="publicKeys">The public keys, as many as the generators.</param>
    /// <param name="additionalAuthenticatedData">The additional authenticated data, with the <see cref="AdditionalDataRole.Authenticated"/> role.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the vectors differ in length or the data does not have the authenticated role.</exception>
    public ProofStatement(P256PointVector generators, P256PointVector publicKeys, AdditionalData additionalAuthenticatedData)
    {
        ArgumentNullException.ThrowIfNull(generators);
        ArgumentNullException.ThrowIfNull(publicKeys);
        ArgumentNullException.ThrowIfNull(additionalAuthenticatedData);
        if(generators.Count != publicKeys.Count)
        {
            throw new ArgumentException("Each generator needs exactly one public key.", nameof(publicKeys));
        }

        if(additionalAuthenticatedData.Role != AdditionalDataRole.Authenticated)
        {
            throw new ArgumentException("The additional authenticated data must have the authenticated role.", nameof(additionalAuthenticatedData));
        }

        Generators = generators;
        PublicKeys = publicKeys;
        AdditionalAuthenticatedData = additionalAuthenticatedData;
    }


    /// <summary>The number of generator and public-key pairs, <c>n + 1</c>.</summary>
    public int Count => Generators.Count;
}
