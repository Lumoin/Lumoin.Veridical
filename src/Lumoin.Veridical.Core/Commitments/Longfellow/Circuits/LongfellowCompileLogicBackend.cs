using System;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The compiling backend, a faithful port of google/longfellow-zk's
/// <c>CompilerBackend&lt;Field&gt;</c> (<c>compiler_backend.h</c>): every primitive forwards directly
/// to the <see cref="LongfellowQuadCircuitBuilder"/>, so the emitted node graph — and
/// therefore the compiled circuit's structure and structural id — is exactly the builder's own.
/// </summary>
/// <remarks>
/// The reference's <c>CompilerBackend::sub</c> composes <c>add(a, mul(konst(mone), b))</c> — it
/// materializes the minus-one constant as a node before multiplying, unlike the builder's own
/// <see cref="LongfellowQuadCircuitBuilder.Sub"/> (the reference's <c>QuadCircuit::sub</c>), which
/// scales directly. The constant-peeking simplifier folds the node form into the same scaled term,
/// so the scheduled circuit is identical either way, but the orphaned constant node stays in the
/// node table and is counted by the dead-node telemetry; <see cref="Sub"/> therefore replicates the
/// backend composition rather than forwarding, keeping every compiler counter equal to the
/// reference's.
/// </remarks>
internal sealed class LongfellowCompileLogicBackend : LongfellowLogicBackend
{
    private readonly LongfellowQuadCircuitBuilder builder;


    /// <summary>
    /// Constructs the backend over a builder and its field-operation bundle.
    /// </summary>
    /// <param name="field">The gadget-layer field-operation bundle.</param>
    /// <param name="builder">The circuit builder every primitive forwards to.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="builder"/> is <see langword="null"/>.</exception>
    public LongfellowCompileLogicBackend(LongfellowLogicFieldOperations field, LongfellowQuadCircuitBuilder builder)
        : base(field)
    {
        ArgumentNullException.ThrowIfNull(builder);

        this.builder = builder;
    }


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.AssertZero"/>.</summary>
    /// <param name="wire">The wire whose value must be zero.</param>
    /// <returns>The assertion node, per <see cref="LongfellowQuadCircuitBuilder.AssertZero"/>.</returns>
    public override int AssertZero(int wire) => builder.AssertZero(wire);


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.Add"/>.</summary>
    /// <param name="left">The first addend node.</param>
    /// <param name="right">The second addend node.</param>
    /// <returns>The sum node.</returns>
    public override int Add(int left, int right) => builder.Add(left, right);


    /// <summary>
    /// The reference's <c>CompilerBackend::sub</c>: <c>add(a, mul(konst(mone), b))</c>, with the
    /// minus-one constant materialized as a node (see the class remarks for why this is not
    /// <see cref="LongfellowQuadCircuitBuilder.Sub"/>).
    /// </summary>
    /// <param name="left">The minuend node.</param>
    /// <param name="right">The subtrahend node.</param>
    /// <returns>The difference node.</returns>
    public override int Sub(int left, int right) => builder.Add(left, builder.Mul(builder.Konst(Field.Compiler.MinusOne.Span), right));


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.Mul(int, int)"/>.</summary>
    /// <param name="left">The first factor node.</param>
    /// <param name="right">The second factor node.</param>
    /// <returns>The product node.</returns>
    public override int Mul(int left, int right) => builder.Mul(left, right);


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.Mul(ReadOnlySpan{byte}, int)"/>.</summary>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="wire">The node to scale.</param>
    /// <returns>The scaled node.</returns>
    public override int MultiplyScaled(ReadOnlySpan<byte> coefficient, int wire) => builder.Mul(coefficient, wire);


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.Mul(ReadOnlySpan{byte}, int, int)"/>.</summary>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="left">The first factor node.</param>
    /// <param name="right">The second factor node.</param>
    /// <returns>The scaled product node.</returns>
    public override int MultiplyScaled(ReadOnlySpan<byte> coefficient, int left, int right) => builder.Mul(coefficient, left, right);


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.Konst"/>.</summary>
    /// <param name="value">The constant, canonical big-endian.</param>
    /// <returns>The constant node.</returns>
    public override int Constant(ReadOnlySpan<byte> value) => builder.Konst(value);


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.Axpy"/>.</summary>
    /// <param name="accumulator">The accumulator node.</param>
    /// <param name="coefficient">The scaling constant, canonical big-endian.</param>
    /// <param name="wire">The scaled node.</param>
    /// <returns>The result node.</returns>
    public override int Axpy(int accumulator, ReadOnlySpan<byte> coefficient, int wire) => builder.Axpy(accumulator, coefficient, wire);


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.Apy"/>.</summary>
    /// <param name="accumulator">The accumulator node.</param>
    /// <param name="constant">The constant to add, canonical big-endian.</param>
    /// <returns>The result node.</returns>
    public override int Apy(int accumulator, ReadOnlySpan<byte> constant) => builder.Apy(accumulator, constant);


    /// <summary>Forwards to <see cref="LongfellowQuadCircuitBuilder.InputWire"/>.</summary>
    /// <returns>The declared input node.</returns>
    public override int InputWire() => builder.InputWire();


    /// <summary>
    /// Forwards to <see cref="LongfellowQuadCircuitBuilder.OutputWire"/>. The parameter order here
    /// (wire, index) already matches the builder's own (node, outputWireId); it is the raw reference
    /// source's <c>output_wire(n, wire_id)</c> that reverses them, so a literal transcription of that
    /// signature would need the swap this port does not.
    /// </summary>
    /// <param name="wire">The node whose value is the output.</param>
    /// <param name="index">The output position the value claims.</param>
    public override void OutputWire(int wire, int index) => builder.OutputWire(wire, index);
}
