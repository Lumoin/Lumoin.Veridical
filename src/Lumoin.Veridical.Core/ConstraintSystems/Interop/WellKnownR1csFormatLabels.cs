using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Wire-format identifier for an R1CS adapter. A reader delegate
/// accepts a <see cref="WellKnownR1csFormatLabel"/> argument and
/// validates that the value matches the format it implements; this
/// is the discriminator that lets one delegate type
/// (<see cref="R1csPipeReaderDelegate"/>) accommodate multiple
/// concrete adapters without conflating their wire formats.
/// </summary>
/// <param name="Identifier">
/// The format identifier in <c>&lt;format&gt;-&lt;version&gt;</c> form.
/// Reserved values are exposed as static properties on the
/// containing struct; applications generally use those rather than
/// constructing identifiers literally.
/// </param>
public readonly record struct WellKnownR1csFormatLabel(string Identifier)
{
    /// <summary>
    /// The iden3 Circom <c>.r1cs</c> binary format version 1. The
    /// canonical specification is at
    /// <c>https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md</c>.
    /// </summary>
    public static WellKnownR1csFormatLabel CircomBinary { get; } =
        new("circom-r1cs-v1");

    /// <summary>
    /// The iden3 Circom <c>.wtns</c> witness binary format version 2,
    /// as emitted by <c>snarkjs</c> and the <c>circom</c>-generated
    /// WebAssembly witness generator.
    /// </summary>
    public static WellKnownR1csFormatLabel CircomWitness { get; } =
        new("circom-wtns-v2");

    /// <summary>
    /// The QED-it ZkInterface v1 format, read by
    /// <see cref="ZkInterface.ZkInterfaceR1csReader"/> (instance) and
    /// <see cref="ZkInterface.ZkInterfaceWitnessReader"/> (witness). The
    /// canonical schema is at
    /// <c>https://github.com/QED-it/zkinterface/blob/master/zkinterface.fbs</c>.
    /// </summary>
    public static WellKnownR1csFormatLabel ZkInterface { get; } =
        new("zkinterface-v1");
}