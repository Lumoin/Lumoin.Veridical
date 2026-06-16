namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The Reed–Solomon evaluation domain of a Ligero instance. Node and point <c>k</c> is always
/// the field element whose bit pattern is <c>k</c> — what differs by field is the arithmetic of
/// their differences, and with it the barycentric weights.
/// <para>
/// Keeping both domains behind one switch is also a validation strategy, not only a feature:
/// the prime-field domain is the simple instantiation — ordinary integer nodes, closed-form
/// weights, easy to check by hand — and everything that consumes a Reed–Solomon codeword
/// (the tableau, the column openings, the proximity argument) is domain-independent and
/// gated over it. The binary-field domain changes only the encoder's weight arithmetic, so a
/// failure there localizes to the encoder rather than to the commitment argument; the same
/// separation lets a faster encoder over either domain be gated purely on reproducing the
/// codewords.
/// </para>
/// </summary>
public enum LigeroNodeDomain
{
    /// <summary>
    /// A large-characteristic prime field, where the node elements behave as the integers
    /// <c>0..n−1</c> and the weights take the factorial closed form. The default.
    /// </summary>
    ConsecutiveIntegers = 0,

    /// <summary>
    /// A binary field (characteristic two), where node differences are XOR —
    /// <c>x_i − x_j = element(i ⊕ j)</c> — and the weights are the generic products over the
    /// XOR distances. The integer factorial form does not apply.
    /// </summary>
    BinaryField = 1,
}
