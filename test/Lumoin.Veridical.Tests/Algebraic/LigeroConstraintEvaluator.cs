using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using System;
using System.Buffers;

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
    /// <summary>The in-memory canonical scalar width in bytes.</summary>
    private const int S = Scalar.SizeBytes;

    /// <summary>The BigInteger reference P-256 base-field addition delegate this evaluator checks constraints with.</summary>
    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    /// <summary>The BigInteger reference P-256 base-field subtraction delegate this evaluator checks constraints with.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    /// <summary>The BigInteger reference P-256 base-field multiplication delegate this evaluator checks constraints with.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();


    /// <summary>Checks the builder's current witness using caller-disposed pooled snapshots.</summary>
    public static bool IsSatisfied(LigeroConstraintSystemBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();
        using IMemoryOwner<byte>? witnessOwner = builder.WitnessBytes();

        return IsSatisfied(builder.LinearConstraints(), (targetsOwner?.Memory ?? Memory<byte>.Empty).Span,
            builder.QuadraticConstraints(), (witnessOwner?.Memory ?? Memory<byte>.Empty).Span);
    }


    /// <summary>Checks all linear and quadratic constraints against borrowed target and witness bytes.</summary>
    public static bool IsSatisfied(
        LigeroLinearConstraint[] linear, ReadOnlySpan<byte> targets, LigeroQuadraticConstraint[] quadratic, ReadOnlySpan<byte> witness)
    {
        ArgumentNullException.ThrowIfNull(linear);
        ArgumentNullException.ThrowIfNull(quadratic);

        //Fold every term into its constraint's running sum, then compare to the target.
        int constraintCount = targets.Length / S;
        byte[] sums = new byte[constraintCount * S];
        Span<byte> product = stackalloc byte[S];
        Span<byte> next = stackalloc byte[S];
        foreach(LigeroLinearConstraint term in linear)
        {
            Span<byte> slot = sums.AsSpan(term.ConstraintIndex * S, S);
            Multiply(term.Coefficient.Span, witness.Slice(term.WitnessIndex * S, S), product, CurveParameterSet.None);
            Add(slot, product, next, CurveParameterSet.None);
            next.CopyTo(slot);
        }

        for(int c = 0; c < constraintCount; c++)
        {
            Subtract(sums.AsSpan(c * S, S), targets.Slice(c * S, S), next, CurveParameterSet.None);
            if(!IsZero(next))
            {
                return false;
            }
        }

        foreach(LigeroQuadraticConstraint q in quadratic)
        {
            Multiply(witness.Slice(q.XIndex * S, S), witness.Slice(q.YIndex * S, S), product, CurveParameterSet.None);
            Subtract(product, witness.Slice(q.ZIndex * S, S), next, CurveParameterSet.None);
            if(!IsZero(next))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Reports whether every byte of a span is zero.</summary>
    /// <param name="value">The bytes to test.</param>
    /// <returns><see langword="true"/> when no byte in <paramref name="value"/> is nonzero.</returns>
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
