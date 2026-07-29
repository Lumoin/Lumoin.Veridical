using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The shared backend surface the Logic/BitW gadgets run against, a faithful port of the reference's
/// backend concept (<c>CompilerBackend&lt;Field&gt;</c>, <c>compiler_backend.h</c>; and
/// <c>EvaluationBackend&lt;Field&gt;</c>, <c>evaluation_backend.h</c>) unified over a single wire
/// handle type. Both reference backends key their wire-like value (<c>V</c>) by an integer — the
/// compiler's node id, the evaluator's value-list index — so this port keeps <see cref="int"/> as the
/// wire handle in both directions and abstracts only the operations.
/// </summary>
/// <remarks>
/// <para>
/// Method mapping: <c>assert0</c>→<see cref="AssertZero"/>, <c>add</c>→<see cref="Add"/>,
/// <c>sub</c>→<see cref="Sub"/>, <c>mul(a,b)</c>→<see cref="Mul"/>, the reference's <c>mul(k,x)</c>
/// and its alias <c>ax(k,x)</c>→<see cref="MultiplyScaled(ReadOnlySpan{byte}, int)"/>, the reference's
/// <c>mul(k,x,y)</c> and its alias <c>axy(k,x,y)</c>→
/// <see cref="MultiplyScaled(ReadOnlySpan{byte}, int, int)"/>, <c>konst</c>→<see cref="Constant"/>,
/// <c>axpy</c>→<see cref="Axpy"/>, <c>apy</c>→<see cref="Apy"/>, <c>input_wire</c>→
/// <see cref="InputWire"/>, <c>output_wire(n, wire_id)</c>→<see cref="OutputWire"/> — note the
/// argument order flip: the reference takes (index, wire) while this port and the underlying
/// <see cref="Compiler.LongfellowQuadCircuitBuilder.OutputWire"/> both take (wire, index).
/// </para>
/// <para>
/// Every primitive is abstract because the two backends implement each one by a genuinely different
/// route (a compiled node versus an evaluated value); only <see cref="InputWire"/> and
/// <see cref="OutputWire"/> get a shared default, since the reference's evaluation backend has no
/// witness-wire concept at all — the evaluating backend intern raw values via <see cref="Constant"/>
/// instead.
/// </para>
/// </remarks>
internal abstract class LongfellowLogicBackend
{
    /// <summary>
    /// Constructs the backend over a field-operation bundle.
    /// </summary>
    /// <param name="field">The field-operation bundle both derived backends consume for their own primitive implementations.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/> is <see langword="null"/>.</exception>
    protected LongfellowLogicBackend(LongfellowLogicFieldOperations field)
    {
        ArgumentNullException.ThrowIfNull(field);

        Field = field;
    }


    /// <summary>The field-operation bundle this backend runs over.</summary>
    public LongfellowLogicFieldOperations Field { get; }


    /// <summary>
    /// The reference's <c>assert0</c>: asserts that a wire's value is zero.
    /// </summary>
    /// <param name="wire">The wire whose value must be zero.</param>
    /// <returns>The asserted wire, or an implementation-specific wire representing the assertion.</returns>
    public abstract int AssertZero(int wire);


    /// <summary>
    /// The reference's <c>add</c>: the sum of two wires.
    /// </summary>
    /// <param name="left">The first addend wire.</param>
    /// <param name="right">The second addend wire.</param>
    /// <returns>The sum wire.</returns>
    public abstract int Add(int left, int right);


    /// <summary>
    /// The reference's <c>sub</c>: the difference of two wires. The compiling backend and the
    /// evaluating backend take genuinely different routes (a composed node versus the field's own
    /// subtraction), so this is not derived from <see cref="Add"/> and <see cref="MultiplyScaled(ReadOnlySpan{byte}, int)"/>.
    /// </summary>
    /// <param name="left">The minuend wire.</param>
    /// <param name="right">The subtrahend wire.</param>
    /// <returns>The difference wire.</returns>
    public abstract int Sub(int left, int right);


    /// <summary>
    /// The reference's <c>mul(a, b)</c>: the product of two wires.
    /// </summary>
    /// <param name="left">The first factor wire.</param>
    /// <param name="right">The second factor wire.</param>
    /// <returns>The product wire.</returns>
    public abstract int Mul(int left, int right);


    /// <summary>
    /// The reference's <c>mul(k, x)</c> (aliased as <c>ax(k, x)</c>): a wire scaled by a constant.
    /// </summary>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="wire">The wire to scale.</param>
    /// <returns>The scaled wire.</returns>
    public abstract int MultiplyScaled(ReadOnlySpan<byte> coefficient, int wire);


    /// <summary>
    /// The reference's <c>mul(k, x, y)</c> (aliased as <c>axy(k, x, y)</c>): the product of two wires
    /// scaled by a constant.
    /// </summary>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="left">The first factor wire.</param>
    /// <param name="right">The second factor wire.</param>
    /// <returns>The scaled product wire.</returns>
    public abstract int MultiplyScaled(ReadOnlySpan<byte> coefficient, int left, int right);


    /// <summary>
    /// The reference's <c>konst</c>: a constant wire.
    /// </summary>
    /// <param name="value">The constant, canonical big-endian.</param>
    /// <returns>The constant wire.</returns>
    public abstract int Constant(ReadOnlySpan<byte> value);


    /// <summary>
    /// The reference's <c>axpy</c>: the fused <c>accumulator + coefficient·wire</c>.
    /// </summary>
    /// <param name="accumulator">The accumulator wire.</param>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="wire">The scaled wire.</param>
    /// <returns>The result wire.</returns>
    public abstract int Axpy(int accumulator, ReadOnlySpan<byte> coefficient, int wire);


    /// <summary>
    /// The reference's <c>apy</c>: the fused <c>accumulator + constant</c>.
    /// </summary>
    /// <param name="accumulator">The accumulator wire.</param>
    /// <param name="constant">The constant to add, canonical big-endian.</param>
    /// <returns>The result wire.</returns>
    public abstract int Apy(int accumulator, ReadOnlySpan<byte> constant);


    /// <summary>
    /// The reference's <c>input_wire</c>: declares a new witness wire. Only the compiling backend
    /// has a witness-wire concept; the base implementation throws.
    /// </summary>
    /// <returns>The declared wire.</returns>
    /// <exception cref="NotSupportedException">When the backend has no witness-wire concept.</exception>
    public virtual int InputWire()
    {
        throw new NotSupportedException("This backend has no witness-wire concept; only the compiling backend declares input wires.");
    }


    /// <summary>
    /// The reference's <c>output_wire(n, wire_id)</c>, argument order flipped to (wire, index):
    /// registers a wire's value as an output claim at a position. Only the compiling backend has an
    /// output-claim concept; the base implementation throws.
    /// </summary>
    /// <param name="wire">The wire whose value is the output.</param>
    /// <param name="index">The output position the value claims.</param>
    /// <exception cref="NotSupportedException">When the backend has no output-claim concept.</exception>
    public virtual void OutputWire(int wire, int index)
    {
        throw new NotSupportedException("This backend has no output-claim concept; only the compiling backend declares output wires.");
    }
}
