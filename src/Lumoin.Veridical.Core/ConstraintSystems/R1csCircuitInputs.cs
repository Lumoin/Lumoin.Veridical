using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The input bindings supplied to <c>R1csCircuit.Compile</c>: a mapping
/// from a declared variable's name to its numeric value. Every declared
/// public input, witness variable, and intermediate variable (except the
/// constant one) must have a binding here.
/// </summary>
/// <remarks>
/// The wrapper exists to give the binding set a named semantic type rather
/// than passing a bare dictionary, and to fix the lookup as case-sensitive
/// (ordinal) so a name declared as <c>"Price"</c> is not satisfied by a
/// binding for <c>"price"</c>. Values are arbitrary-precision integers;
/// the compiler reduces them modulo the scalar field order.
/// </remarks>
public sealed class R1csCircuitInputs
{
    private readonly Dictionary<string, BigInteger> bindings;


    /// <summary>
    /// Wraps a name-to-value mapping. The mapping is copied into an
    /// ordinal-keyed dictionary; the source is not retained.
    /// </summary>
    /// <param name="bindings">The name-to-value bindings. Must be non-empty.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="bindings"/> is null.</exception>
    /// <exception cref="ArgumentException">When <paramref name="bindings"/> is empty.</exception>
    public R1csCircuitInputs(IReadOnlyDictionary<string, BigInteger> bindings)
    {
        ArgumentNullException.ThrowIfNull(bindings);

        if(bindings.Count == 0)
        {
            throw new ArgumentException("Circuit inputs must bind at least one variable.", nameof(bindings));
        }

        this.bindings = new Dictionary<string, BigInteger>(bindings, StringComparer.Ordinal);
    }


    /// <summary>The number of bound names.</summary>
    public int Count => bindings.Count;


    /// <summary>
    /// Looks up the value bound to <paramref name="name"/> (case-sensitive),
    /// returning <see langword="false"/> when no binding exists.
    /// </summary>
    public bool TryGetValue(string name, out BigInteger value) => bindings.TryGetValue(name, out value);
}
