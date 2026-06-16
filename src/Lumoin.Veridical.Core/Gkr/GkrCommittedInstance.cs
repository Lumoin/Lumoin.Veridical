namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// One circuit instance of a committed-witness proof: a data-parallel circuit and its copy
/// count. Several instances may prove against one shared Ligero commitment — each instance's
/// copy-major input table is a consecutive segment of the committed witness, in declaration
/// order, and the public statement constraints relate wires across segments. This is how
/// heterogeneous sub-circuits compose under the uniform-copy rule: every copy of one instance
/// shares its wiring, while instances differ freely.
/// </summary>
internal readonly record struct GkrCommittedInstance(GkrCircuit Circuit, int CopyCount);
