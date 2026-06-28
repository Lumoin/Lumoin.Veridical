using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Common;

/// <summary>
/// A general-purpose builder implementing a fold/aggregate pattern with a
/// fluent interface: a sequence of transformation functions is applied to a
/// seed <typeparamref name="TResult"/> in order, each receiving the
/// accumulated result, the builder (for non-moving configuration), and the
/// build state.
/// </summary>
/// <typeparam name="TResult">The type being built.</typeparam>
/// <typeparam name="TState">The build-state side-channel passed to every transformation.</typeparam>
/// <typeparam name="TBuilder">The concrete builder type (CRTP), enabling fluent chaining.</typeparam>
/// <remarks>
/// <para>
/// This is the synchronous Veridical adaptation of the Verifiable library's
/// <c>Builder&lt;TResult, TState, TBuilder&gt;</c>. Circuit construction is pure
/// CPU work — no I/O, signing, or external resolution — so the async surface
/// (<c>ValueTask</c>, <see cref="System.Threading.CancellationToken"/>,
/// <c>BuildAsync</c>) is stripped: a transformation is a plain
/// <c>Func&lt;TResult, TBuilder, TState?, TResult&gt;</c> and <c>Build</c> is
/// synchronous.
/// </para>
/// <para>
/// The fold is <c>fold(f, seed, [T1..Tn]) = Tn(...T2(T1(seed))...)</c>.
/// Transformations are added with <see cref="With"/>; the fold runs only in a
/// <c>Build</c> overload. A configured builder is therefore a program stored
/// as data — a list of transformations that is inspectable, reusable, and
/// (because the fold is deferred and pure) deterministic: two identically
/// configured builders produce equal results. The invariant-preservation
/// argument holds: if the seed satisfies invariant I and every transformation
/// preserves I, the result satisfies I.
/// </para>
/// <para>
/// Unlike the Verifiable base, this one does not require
/// <c>TResult : new()</c> and offers no default-constructed-seed
/// <c>Build()</c>. Veridical's results (notably <see cref="ConstraintSystems.R1csCircuit"/>) are
/// immutable types with no parameterless constructor — the canonical types are
/// unchanged from their original form — so the seed is always supplied:
/// <see cref="Build()"/> is abstract and a derived builder constructs the
/// appropriate seed before folding.
/// </para>
/// </remarks>
public abstract class R1csBuilder<TResult, TState, TBuilder>
    where TBuilder : R1csBuilder<TResult, TState, TBuilder>
    where TState : IBuilderState
{
    /// <summary>
    /// The transformations applied, in addition order, during a build. The
    /// only accumulation mechanism — domain-specific fluent methods append
    /// here via <see cref="With"/>.
    /// </summary>
    protected List<Func<TResult, TBuilder, TState?, TResult>> WithActions { get; } = [];


    /// <summary>Initialises an empty builder with no transformations.</summary>
    protected R1csBuilder()
    {
    }


    /// <summary>
    /// Appends a transformation to the fold pipeline and returns this builder
    /// for chaining. Transformations should be pure and deterministic.
    /// </summary>
    /// <param name="action">The transformation: it receives the accumulated result, this builder, and the build state, and returns the next accumulated result.</param>
    /// <returns>This builder, typed as <typeparamref name="TBuilder"/>.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="action"/> is null.</exception>
    public TBuilder With(Func<TResult, TBuilder, TState?, TResult> action)
    {
        ArgumentNullException.ThrowIfNull(action);

        WithActions.Add(action);

        return (TBuilder)this;
    }


    /// <summary>
    /// Builds the result. A derived builder supplies the seed (Veridical's
    /// results are immutable and not default-constructible) and folds it,
    /// typically via <see cref="Build(TResult)"/>.
    /// </summary>
    public abstract TResult Build();


    /// <summary>Folds the registered transformations over <paramref name="seed"/> with no build state.</summary>
    public virtual TResult Build(TResult seed)
    {
        return Fold(seed, default);
    }


    /// <summary>Folds the registered transformations over <paramref name="seed"/> with the supplied <paramref name="state"/>.</summary>
    public virtual TResult BuildWithState(TResult seed, TState state)
    {
        return Fold(seed, state);
    }


    private TResult Fold(TResult seed, TState? state)
    {
        TResult result = seed;
        foreach(Func<TResult, TBuilder, TState?, TResult> action in WithActions)
        {
            result = action(result, (TBuilder)this, state);
        }

        return result;
    }
}
