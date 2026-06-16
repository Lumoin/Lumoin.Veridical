using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Thrown by an R1CS adapter when the file's declared field modulus
/// does not match the curve the caller passed in. The exception is a
/// parsing concern, not a constraint-system concern; it lives in
/// the Interop namespace so the algebraic surface in
/// <see cref="Lumoin.Veridical.Core.ConstraintSystems"/> is not
/// polluted by file-format errors.
/// </summary>
public sealed class R1csUnsupportedFieldException: Exception
{
    /// <summary>The big-endian hex of the modulus the curve declares.</summary>
    public string ExpectedModulusHex { get; }

    /// <summary>The big-endian hex of the modulus the file declared.</summary>
    public string FoundModulusHex { get; }


    /// <summary>Initialises the exception with the two moduli to compare.</summary>
    public R1csUnsupportedFieldException(
        string expectedModulusHex,
        string foundModulusHex)
        : base(BuildMessage(expectedModulusHex, foundModulusHex))
    {
        ExpectedModulusHex = expectedModulusHex;
        FoundModulusHex = foundModulusHex;
    }


    /// <inheritdoc/>
    public R1csUnsupportedFieldException()
        : this(string.Empty, string.Empty)
    {
    }


    /// <inheritdoc/>
    public R1csUnsupportedFieldException(string message)
        : base(message)
    {
        ExpectedModulusHex = string.Empty;
        FoundModulusHex = string.Empty;
    }


    /// <inheritdoc/>
    public R1csUnsupportedFieldException(string message, Exception innerException)
        : base(message, innerException)
    {
        ExpectedModulusHex = string.Empty;
        FoundModulusHex = string.Empty;
    }


    private static string BuildMessage(string expected, string found) =>
        $"The R1CS file declares field modulus 0x{found} which does not match the curve's expected modulus 0x{expected}. Compile the Circom circuit with the `-p bls12381` flag to produce a BLS12-381-compatible R1CS file.";
}