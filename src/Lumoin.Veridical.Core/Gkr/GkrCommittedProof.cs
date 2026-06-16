using Lumoin.Veridical.Core.Commitments.Ligero;
using System;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// A committed-witness GKR proof: one data-parallel circuit proof per instance plus the Ligero
/// proof that the committed witness — whose tableau root seeded the GKR transcript — evaluates
/// to every walk's final input claims at the derived tensor points. The inputs stay private:
/// the verifier sees the circuits, the claimed outputs, and this proof. Ligero is in its small
/// Longfellow role here (one witness commitment and two linear opening constraints per
/// instance), not over the circuits.
/// </summary>
internal sealed class GkrCommittedProof: IDisposable
{
    public GkrDataParallelProof[] CircuitProofs { get; }

    public GkrDataParallelProof CircuitProof => CircuitProofs[0];

    public LigeroProof WitnessProof { get; }


    internal GkrCommittedProof(GkrDataParallelProof circuitProof, LigeroProof witnessProof)
        : this([circuitProof], witnessProof)
    {
    }


    internal GkrCommittedProof(GkrDataParallelProof[] circuitProofs, LigeroProof witnessProof)
    {
        CircuitProofs = circuitProofs;
        WitnessProof = witnessProof;
    }


    public void Dispose()
    {
        foreach(GkrDataParallelProof circuitProof in CircuitProofs)
        {
            circuitProof.Dispose();
        }

        WitnessProof.Dispose();
    }
}
