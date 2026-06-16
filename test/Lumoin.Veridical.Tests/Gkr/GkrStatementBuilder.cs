using Lumoin.Veridical.Core.Commitments.Ligero;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// Accumulates the public statement over a committed witness: copy-to-copy wire equalities and
/// public-value pins as sparse linear constraints with their targets, in the index space of the
/// concatenated witness. The negation coefficient an equality subtracts with is the FIELD'S —
/// the Fp256 <c>p − 1</c> by default, the element one over a binary field (where subtraction is
/// addition). The coefficient is a constructor parameter rather than a constant because a
/// wrong-field −1 makes every equality unsatisfiable — and an unsatisfiable statement makes
/// rejection tests pass vacuously, so the failure mode is silent. Field-generic code takes its
/// constants from the field; the suite runs the same machinery over both a large-characteristic
/// prime field and a characteristic-two field because each falsifies assumptions the other
/// cannot express.
/// </summary>
internal sealed class GkrStatementBuilder
{
    private static byte[] Zero { get; } = GkrTestSupport.Scalar(0);

    private readonly List<LigeroLinearConstraint> terms = [];
    private readonly List<byte> targets = [];
    private int constraint;


    private byte[] NegativeOne { get; }


    /// <summary>A statement builder over the Fp256 reference field.</summary>
    public GkrStatementBuilder()
        : this(GkrTestSupport.NegativeOne)
    {
    }


    /// <summary>A statement builder with an explicit negation coefficient — pass the field's
    /// <c>−1</c> (the element one for characteristic two).</summary>
    public GkrStatementBuilder(byte[] negativeOne) => NegativeOne = negativeOne;


    /// <summary>The number of constraints accumulated so far — the index the next one gets.</summary>
    public int ConstraintCount => constraint;


    public void Equal(int leftIndex, int rightIndex)
    {
        terms.Add(new LigeroLinearConstraint(constraint, leftIndex, GkrTestSupport.One));
        terms.Add(new LigeroLinearConstraint(constraint, rightIndex, NegativeOne));
        targets.AddRange(Zero);
        constraint++;
    }


    public void Pin(int witnessIndex, int bit)
    {
        terms.Add(new LigeroLinearConstraint(constraint, witnessIndex, GkrTestSupport.One));
        targets.AddRange(bit == 1 ? GkrTestSupport.One : Zero);
        constraint++;
    }


    public void PinWord(int witnessBase, uint word)
    {
        for(int i = 0; i < 32; i++)
        {
            Pin(witnessBase + i, (int)((word >> i) & 1));
        }
    }


    public (LigeroLinearConstraint[] Constraints, byte[] Targets) Build() => ([.. terms], [.. targets]);
}
