using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// A direct, prover-independent evaluator of the Ligero constraint system: given a
/// candidate witness vector it checks every linear constraint
/// (<c>Σ coefficient·W == target</c>) and quadratic constraint
/// (<c>W[z] == W[x]·W[y]</c>) over the P-256 base field, mirroring the satisfaction
/// <see cref="LigeroProver"/> enforces before it will emit a proof. It lets a test
/// inject a <em>malicious</em> witness — one the honest builder would never compute
/// (via <see cref="LigeroConstraintSystemBuilder.SetWireForTesting"/>) — and assert
/// the constraint system rejects it, isolating soundness from the slow prove path.
/// <para>
/// The isolation is the point, and it is a layering principle used throughout this
/// suite: "is the STATEMENT right" (does this constraint system accept exactly the
/// intended witnesses) is a different question from "is the PROVER right" (does the
/// proof system faithfully prove a satisfied system), and conflating them buys
/// multi-minute proof runs that cannot say which layer failed. The cheap evaluator
/// answers the first question in milliseconds — including for adversarial witnesses a
/// prove could never exercise, since the prover refuses unsatisfied systems outright —
/// while a small number of slow end-to-end gates answer the second.
/// </para>
/// </summary>
internal static class LigeroConstraintEvaluator
{
    private const int S = Scalar.SizeBytes;

    private static readonly ScalarAddDelegate Add = P256BaseFieldReference.GetAdd();
    private static readonly ScalarSubtractDelegate Subtract = P256BaseFieldReference.GetSubtract();
    private static readonly ScalarMultiplyDelegate Multiply = P256BaseFieldReference.GetMultiply();


    //True iff the builder's current witness satisfies every constraint. Reads
    //WitnessBytes(), so a prior SetWireForTesting is reflected.
    public static bool IsSatisfied(LigeroConstraintSystemBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return IsSatisfied(builder.LinearConstraints(), builder.TargetBytes(), builder.QuadraticConstraints(), builder.WitnessBytes());
    }


    public static bool IsSatisfied(
        LigeroLinearConstraint[] linear, byte[] targets, LigeroQuadraticConstraint[] quadratic, byte[] witness)
    {
        ArgumentNullException.ThrowIfNull(linear);
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(quadratic);
        ArgumentNullException.ThrowIfNull(witness);

        //Fold every term into its constraint's running sum, then compare to the target.
        int constraintCount = targets.Length / S;
        byte[] sums = new byte[constraintCount * S];
        Span<byte> product = stackalloc byte[S];
        Span<byte> next = stackalloc byte[S];
        foreach(LigeroLinearConstraint term in linear)
        {
            Span<byte> slot = sums.AsSpan(term.ConstraintIndex * S, S);
            Multiply(term.Coefficient.Span, witness.AsSpan(term.WitnessIndex * S, S), product, CurveParameterSet.None);
            Add(slot, product, next, CurveParameterSet.None);
            next.CopyTo(slot);
        }

        for(int c = 0; c < constraintCount; c++)
        {
            Subtract(sums.AsSpan(c * S, S), targets.AsSpan(c * S, S), next, CurveParameterSet.None);
            if(!IsZero(next))
            {
                return false;
            }
        }

        foreach(LigeroQuadraticConstraint q in quadratic)
        {
            Multiply(witness.AsSpan(q.XIndex * S, S), witness.AsSpan(q.YIndex * S, S), product, CurveParameterSet.None);
            Subtract(product, witness.AsSpan(q.ZIndex * S, S), next, CurveParameterSet.None);
            if(!IsZero(next))
            {
                return false;
            }
        }

        return true;
    }


    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        foreach(byte b in value)
        {
            if(b != 0)
            {
                return false;
            }
        }

        return true;
    }
}
