using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Receives the decoded contents of a ZkInterface message stream as a
/// sequence of push callbacks. This is the consumer half of the
/// FlatBuffers swap seam: a <see cref="ZkInterfaceMessageDecoderDelegate"/>
/// reads the wire format — with whatever FlatBuffers implementation it
/// chooses — and pushes the fields it finds here.
/// </summary>
/// <remarks>
/// <para>
/// The callbacks pass <see cref="ReadOnlySpan{T}"/> over the decoder's
/// own buffer, so nothing is materialised onto the managed heap at the
/// seam: a sink that needs to retain bytes copies them into its own
/// (typically pooled) storage during the call, and a sink that does not
/// care simply ignores them. This is what lets the reader stay
/// allocation-lean and keep field elements out of the GC heap — a
/// pull/<c>IAsyncEnumerable</c> contract cannot, because a span cannot
/// cross a <c>yield</c>/<c>await</c> boundary.
/// </para>
/// <para>
/// All methods default to no-ops, so a sink implements only the messages
/// it consumes (the instance builder ignores witness variables; a witness
/// builder ignores constraints). Spans passed to the callbacks are valid
/// only for the duration of the call.
/// </para>
/// <para>
/// Field-element bytes (instance/witness values and constraint
/// coefficients) are little-endian, as ZkInterface stores them.
/// </para>
/// </remarks>
public interface IZkInterfaceMessageSink
{
    /// <summary>
    /// The circuit's <c>field_maximum</c> — the canonical little-endian
    /// field order minus one — from a <c>CircuitHeader</c>. Called only
    /// when the header declares the field.
    /// </summary>
    void OnFieldMaximum(ReadOnlySpan<byte> fieldMaximumLittleEndian) { }

    /// <summary>The header's <c>free_variable_id</c>: a variable ID greater than every ID the producer allocated.</summary>
    void OnFreeVariableId(ulong freeVariableId) { }

    /// <summary>
    /// One instance (public) variable from <c>CircuitHeader.instance_variables</c>.
    /// The value span is empty when the header omits values (for example in a
    /// preprocessing phase).
    /// </summary>
    void OnInstanceVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian) { }

    /// <summary>Opens a new bilinear constraint; terms reported until the matching <see cref="EndConstraint"/> belong to it.</summary>
    void BeginConstraint() { }

    /// <summary>One (variable, coefficient) term of the current constraint's <paramref name="matrix"/> linear combination.</summary>
    void OnConstraintTerm(ZkInterfaceConstraintMatrix matrix, ulong variableId, ReadOnlySpan<byte> coefficientLittleEndian) { }

    /// <summary>Closes the constraint opened by the most recent <see cref="BeginConstraint"/>.</summary>
    void EndConstraint() { }

    /// <summary>One assigned variable from a <c>Witness</c> message's <c>assigned_variables</c>.</summary>
    void OnWitnessVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian) { }
}
