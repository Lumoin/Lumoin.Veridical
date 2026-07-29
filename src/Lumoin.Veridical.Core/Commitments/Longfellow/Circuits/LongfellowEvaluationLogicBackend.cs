using System;
using System.Collections.Generic;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The evaluating backend, a faithful port of google/longfellow-zk's
/// <c>EvaluationBackend&lt;Field&gt;</c> (<c>evaluation_backend.h</c>): every primitive computes a
/// concrete field value directly, rather than building a node graph. Values are interned into a list
/// as they are produced, and the wire handle is the list index — the reference's <c>V</c> struct
/// wraps an <c>Elt</c> directly, but this port keeps <see cref="int"/> as the wire handle in both
/// backends (<see cref="LongfellowLogicBackend"/>'s class remarks).
/// </summary>
/// <remarks>
/// <para>
/// The reference destructor panics if <c>assertion_failed_</c> is still set when the backend is
/// destroyed, a test-hygiene aid catching a caller that forgot to read <c>assertion_failed()</c>.
/// This port drops that check: it needs a finalizer to reproduce, and a buffer-touching finalizer is
/// itself a documented hazard in this codebase (a missed <see cref="IDisposable.Dispose"/> elsewhere
/// orphans pooled memory rather than safely finalizing). The latch itself, and the read-and-reset
/// semantics of <see cref="AssertionFailed"/>, are kept; callers are expected to read it explicitly,
/// exactly as the reference's tests do before the destructor would otherwise fire.
/// </para>
/// <para>
/// Unlike the reference, which has no <c>input_wire</c>/<c>output_wire</c> on this backend at all,
/// this port inherits <see cref="LongfellowLogicBackend"/>'s throwing defaults for both rather than
/// omitting the members, keeping one abstract surface across both backends.
/// </para>
/// </remarks>
internal sealed class LongfellowEvaluationLogicBackend : LongfellowLogicBackend
{
    private readonly List<byte[]> values = [];
    private readonly bool panicOnAssertionFailure;
    private bool assertionFailed;


    /// <summary>
    /// Constructs the backend over a field-operation bundle.
    /// </summary>
    /// <param name="field">The gadget-layer field-operation bundle.</param>
    /// <param name="panicOnAssertionFailure">When <see langword="true"/> (the default), <see cref="AssertZero"/> throws on a nonzero value; when <see langword="false"/>, it latches <see cref="AssertionFailed"/> instead.</param>
    public LongfellowEvaluationLogicBackend(LongfellowLogicFieldOperations field, bool panicOnAssertionFailure = true)
        : base(field)
    {
        this.panicOnAssertionFailure = panicOnAssertionFailure;
    }


    /// <summary>
    /// Reads the reference's <c>assertion_failed()</c>: returns whether an assertion has failed since
    /// the last read, and resets the latch.
    /// </summary>
    public bool AssertionFailed
    {
        get
        {
            bool failed = assertionFailed;
            assertionFailed = false;

            return failed;
        }
    }


    /// <summary>
    /// Returns the canonical bytes a wire holds, for test and assertion use.
    /// </summary>
    /// <param name="wire">The wire to read.</param>
    /// <returns>The wire's value, canonical big-endian.</returns>
    public ReadOnlyMemory<byte> ElementAt(int wire) => values[wire];


    /// <summary>
    /// The reference's <c>assert0</c>: when the wire's value is zero, returns it unchanged; otherwise
    /// either throws or latches <see cref="AssertionFailed"/>, depending on how this backend was
    /// constructed.
    /// </summary>
    /// <param name="wire">The wire whose value must be zero.</param>
    /// <returns><paramref name="wire"/>, unchanged.</returns>
    /// <exception cref="InvalidOperationException">When the value is nonzero and this backend panics on assertion failure.</exception>
    public override int AssertZero(int wire)
    {
        if(LongfellowCompilerFieldOperations.ElementIsZero(values[wire]))
        {
            return wire;
        }

        if(panicOnAssertionFailure)
        {
            throw new InvalidOperationException("The evaluation backend asserted a nonzero value to be zero.");
        }

        assertionFailed = true;

        return wire;
    }


    /// <summary>The reference's <c>add</c>: the field sum of two wires' values.</summary>
    /// <param name="left">The first addend wire.</param>
    /// <param name="right">The second addend wire.</param>
    /// <returns>The interned sum wire.</returns>
    public override int Add(int left, int right)
    {
        var sum = new byte[Scalar.SizeBytes];
        Field.Compiler.Add(values[left], values[right], sum, Field.Compiler.Curve);

        return Intern(sum);
    }


    /// <summary>The reference's <c>sub</c>: the field difference of two wires' values, via <see cref="LongfellowLogicFieldOperations.Subtract"/> (a genuine field operation, not composed from multiplication and addition).</summary>
    /// <param name="left">The minuend wire.</param>
    /// <param name="right">The subtrahend wire.</param>
    /// <returns>The interned difference wire.</returns>
    public override int Sub(int left, int right)
    {
        var difference = new byte[Scalar.SizeBytes];
        Field.Subtract(values[left], values[right], difference, Field.Compiler.Curve);

        return Intern(difference);
    }


    /// <summary>The reference's <c>mul(a, b)</c>: the field product of two wires' values.</summary>
    /// <param name="left">The first factor wire.</param>
    /// <param name="right">The second factor wire.</param>
    /// <returns>The interned product wire.</returns>
    public override int Mul(int left, int right)
    {
        var product = new byte[Scalar.SizeBytes];
        Field.Compiler.Multiply(values[left], values[right], product, Field.Compiler.Curve);

        return Intern(product);
    }


    /// <summary>The reference's <c>mul(k, x)</c>: a wire's value scaled by a constant.</summary>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="wire">The wire to scale.</param>
    /// <returns>The interned scaled wire.</returns>
    public override int MultiplyScaled(ReadOnlySpan<byte> coefficient, int wire)
    {
        var product = new byte[Scalar.SizeBytes];
        Field.Compiler.Multiply(coefficient, values[wire], product, Field.Compiler.Curve);

        return Intern(product);
    }


    /// <summary>The reference's <c>mul(k, x, y)</c>: the product of two wires' values scaled by a constant, computed as <c>k·(x·y)</c>.</summary>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="left">The first factor wire.</param>
    /// <param name="right">The second factor wire.</param>
    /// <returns>The interned scaled product wire.</returns>
    public override int MultiplyScaled(ReadOnlySpan<byte> coefficient, int left, int right)
    {
        var innerProduct = new byte[Scalar.SizeBytes];
        Field.Compiler.Multiply(values[left], values[right], innerProduct, Field.Compiler.Curve);

        var scaled = new byte[Scalar.SizeBytes];
        Field.Compiler.Multiply(coefficient, innerProduct, scaled, Field.Compiler.Curve);

        return Intern(scaled);
    }


    /// <summary>The reference's <c>konst</c>: interns a raw value as a wire, with no dependency on any other wire. This is also how this port represents the reference's direct <c>V{x}</c> construction, since the evaluating backend has no witness-wire concept of its own.</summary>
    /// <param name="value">The constant, canonical big-endian.</param>
    /// <returns>The interned constant wire.</returns>
    public override int Constant(ReadOnlySpan<byte> value) => Intern(value.ToArray());


    /// <summary>The reference's <c>axpy</c>: <c>accumulator + coefficient·wire</c>, computed directly through the field's addition and multiplication.</summary>
    /// <param name="accumulator">The accumulator wire.</param>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="wire">The scaled wire.</param>
    /// <returns>The interned result wire.</returns>
    public override int Axpy(int accumulator, ReadOnlySpan<byte> coefficient, int wire)
    {
        var scaled = new byte[Scalar.SizeBytes];
        Field.Compiler.Multiply(coefficient, values[wire], scaled, Field.Compiler.Curve);

        var sum = new byte[Scalar.SizeBytes];
        Field.Compiler.Add(values[accumulator], scaled, sum, Field.Compiler.Curve);

        return Intern(sum);
    }


    /// <summary>The reference's <c>apy</c>: <c>accumulator + constant</c>.</summary>
    /// <param name="accumulator">The accumulator wire.</param>
    /// <param name="constant">The constant to add, canonical big-endian.</param>
    /// <returns>The interned result wire.</returns>
    public override int Apy(int accumulator, ReadOnlySpan<byte> constant)
    {
        var sum = new byte[Scalar.SizeBytes];
        Field.Compiler.Add(values[accumulator], constant, sum, Field.Compiler.Curve);

        return Intern(sum);
    }


    /// <summary>
    /// Interns a computed value, returning its index as the wire handle.
    /// </summary>
    /// <param name="value">The value to intern, canonical big-endian.</param>
    /// <returns>The new wire's index.</returns>
    private int Intern(byte[] value)
    {
        int index = values.Count;
        values.Add(value);

        return index;
    }
}
