namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// The members of the ZkInterface <c>Message</c> union, identified by the
/// <c>Root.message_type</c> discriminator byte. The numeric values are the
/// FlatBuffers union tags fixed by the schema declaration order in
/// <c>zkinterface.fbs</c>: <c>None</c> is the absent-union sentinel (tag 0)
/// and the rest follow in declaration order.
/// </summary>
internal enum ZkInterfaceMessageType : byte
{
    /// <summary>No message present (the FlatBuffers union NONE sentinel).</summary>
    None = 0,

    /// <summary>A <c>CircuitHeader</c>: instance variables, free-variable id, and field maximum.</summary>
    CircuitHeader = 1,

    /// <summary>A <c>ConstraintSystem</c>: a batch of bilinear (R1CS) constraints.</summary>
    ConstraintSystem = 2,

    /// <summary>A <c>Witness</c>: an assignment of values to variables.</summary>
    Witness = 3,

    /// <summary>A <c>Command</c>: a gadget-flow request (not interpreted by this reader).</summary>
    Command = 4,
}
