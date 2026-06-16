using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;

namespace Lumoin.Veridical.Analysis.Simulation;

/// <summary>
/// Builds a <see cref="PolynomialCommitmentProvider"/> bound to the given
/// squeeze delegate. A simulator injects a recording or replay squeeze into
/// every provider a protocol run constructs — the provider captures its
/// squeeze at creation, so the injection point must sit inside the factory
/// rather than at the protocol call.
/// </summary>
/// <param name="squeeze">The XOF delegate the provider is to capture.</param>
/// <returns>The provider; the consumer owns disposal.</returns>
public delegate PolynomialCommitmentProvider SqueezeBoundProviderFactory(FiatShamirSqueezeDelegate squeeze);
