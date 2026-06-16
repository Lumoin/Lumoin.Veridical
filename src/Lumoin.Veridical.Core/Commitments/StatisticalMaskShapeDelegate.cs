using Lumoin.Veridical.Core.Commitments.BaseFold;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Resolves the statistical sumcheck mask's commitment shape for a masked
/// sumcheck of the given variable count and per-variable degree, under the
/// scheme's own ledger (<c>ZK-STATMASK-DESIGN.md</c> §3): the
/// lifted-and-filled BaseFold resolution for hash-path providers, the
/// unlifted Pedersen/IPA resolution for Hyrax. Deterministic — the prover and
/// verifier resolve it independently from the protocol shape, with no wire
/// data.
/// </summary>
/// <param name="sumcheckVariableCount">The masked sumcheck's variable count <c>d</c>.</param>
/// <param name="perVariableDegree">The mask univariates' degree, matching the masked round format; in <c>[2, 3]</c>.</param>
/// <returns>The resolved shape.</returns>
public delegate StatisticalMaskParameters StatisticalMaskShapeDelegate(
    int sumcheckVariableCount,
    int perVariableDegree);
