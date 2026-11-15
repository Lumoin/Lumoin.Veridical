using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The key material <c>K = KDF(Z_AB, A)</c> an ECIES key derivation produced (Verheul Annex A.4): the AEAD key
/// followed by the initialisation vector, split as the <see cref="EciesParameterSet"/> recorded in the tag says.
/// It is also the value a key holder returns when it performs the Diffie-Hellman agreement and the key derivation
/// itself, as a PKCS#11 <c>CKM_ECDH1_DERIVE</c> mechanism does.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The key material never leaves the party that derived it, and the caller disposes it, which
/// clears its memory. Algorithm 18 step 5 requires <c>K</c> to be deleted after use; disposing does that.
/// </remarks>
public sealed class DerivedKeyMaterial: SensitiveMemory
{
    /// <summary>The parameter set this key material was derived under, from its tag.</summary>
    public EciesParameterSet Parameters => Tag.Get<EciesParameterSet>();


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct key material.</summary>
    internal DerivedKeyMaterial(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies key material a key holder derived into a pool-rented buffer and returns it wrapped.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="EciesParameterSet.KeyMaterialSizeBytes"/> bytes: the key, then the IV.</param>
    /// <param name="parameters">The parameter set the material was derived under.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>Key material wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="parameters"/> is invalid or <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static DerivedKeyMaterial FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        EciesParameterSet parameters,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        parameters.Validate();
        if(canonicalBytes.Length != parameters.KeyMaterialSizeBytes)
        {
            throw new ArgumentException(
                $"Key material for this parameter set must be exactly {parameters.KeyMaterialSizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(parameters.KeyMaterialSizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        return new DerivedKeyMaterial(owner, TagFor(parameters, tag));
    }


    /// <summary>Returns the AEAD key: the leading <see cref="EciesParameterSet.KeySizeBytes"/> bytes.</summary>
    public ReadOnlySpan<byte> GetKeyBytes() => AsReadOnlySpan()[..Parameters.KeySizeBytes];


    /// <summary>Returns the initialisation vector: the <see cref="EciesParameterSet.IvSizeBytes"/> bytes that follow the key.</summary>
    public ReadOnlySpan<byte> GetIvBytes() => AsReadOnlySpan().Slice(Parameters.KeySizeBytes, Parameters.IvSizeBytes);


    /// <summary>Builds the tag of key material under <paramref name="parameters"/>, merged with an optional provenance tag.</summary>
    internal static Tag TagFor(EciesParameterSet parameters, Tag? tag)
    {
        Tag baseTag = tag ?? Tag.Empty;

        return baseTag.With(SecdsaStructureKind.DerivedKeyMaterial).With(parameters);
    }
}
