using System.Diagnostics;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Which hash of the transferable proof a <see cref="ProofDigest"/> is.
/// </summary>
/// <param name="Identifier">The stable name of the kind.</param>
[DebuggerDisplay("{Identifier,nq}")]
public readonly record struct ProofDigestKind(string Identifier)
{
    /// <summary>The primary hash <c>H1 = H(e₀ ‖ … ‖ eₙ)</c>: the preimage the prover returns as its response (Verheul Protocol 2 and Algorithm 23 step 12).</summary>
    public static ProofDigestKind Primary { get; } = new("primary");

    /// <summary>The secondary hash <c>H2 = H(H1)</c> carried in the challenge, which lets a third party verify the response without learning the ephemeral keys (Algorithm 22 step 5).</summary>
    public static ProofDigestKind Secondary { get; } = new("secondary");
}
