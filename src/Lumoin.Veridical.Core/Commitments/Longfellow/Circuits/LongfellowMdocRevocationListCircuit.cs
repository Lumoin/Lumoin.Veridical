using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The small-list revocation statement, a faithful port of google/longfellow-zk's
/// <c>MdocRevocationList</c> (<c>circuits/tests/mdoc/mdoc_revocation.h</c>): the prover shows a
/// credential identifier differs from every identifier on a revocation list by exhibiting the
/// inverse of <c>Π (list[i] − id)</c> — the product is nonzero exactly when the identifier is on
/// no list position.
/// </summary>
/// <remarks>
/// The list occupies public input wires, so this statement fits lists the verifier itself holds:
/// the verifier learns nothing about the identifier beyond its absence from the list, and the
/// prover cannot satisfy the statement for a listed identifier because the product's inverse does
/// not exist (the host-side witness helper then emits zero under the Fermat zero-maps-to-zero
/// convention, and the equality assertion fails). The reference positions this shape for small
/// lists; the span statement (<see cref="LongfellowMdocRevocationSpanCircuit"/>) serves large ones.
/// </remarks>
internal sealed class LongfellowMdocRevocationListCircuit
{
    private readonly LongfellowLogic logic;


    /// <summary>
    /// Constructs the statement over a gadget layer.
    /// </summary>
    /// <param name="logic">The gadget layer to build on.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    public LongfellowMdocRevocationListCircuit(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        this.logic = logic;
    }


    /// <summary>
    /// The reference's <c>assert_not_on_list</c>: asserts <c>Π (list[i] − id) · productInverse
    /// == 1</c> over the reference's balanced product tree, which can hold only when every factor —
    /// and hence every difference from a listed identifier — is nonzero.
    /// </summary>
    /// <param name="list">The revocation list's element wires (public).</param>
    /// <param name="id">The identifier wire (private witness).</param>
    /// <param name="productInverse">The claimed inverse of the difference product (private witness).</param>
    /// <exception cref="ArgumentNullException">When <paramref name="list"/> is <see langword="null"/>.</exception>
    public void AssertNotOnList(int[] list, int id, int productInverse)
    {
        ArgumentNullException.ThrowIfNull(list);

        int product = logic.Multiply(0, list.Length, i => logic.Backend.Sub(list[i], id));
        int wantOne = logic.Backend.Mul(product, productInverse);
        _ = logic.AssertEqual(wantOne, logic.Backend.Constant(logic.Field.Compiler.One.Span));
    }
}
