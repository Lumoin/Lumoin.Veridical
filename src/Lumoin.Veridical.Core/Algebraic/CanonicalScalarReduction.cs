using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Branch-free subtraction and single-step reduction of canonical big-endian scalar bytes.
/// </summary>
/// <remarks>
/// The borrow chain and constant-time mask selection process every byte without data-dependent branches
/// or early exits, so witness and nonce material do not control their timing. Length checks depend only on
/// public span sizes. As with the repository's constant-time comparisons, this is best-effort in managed
/// code: the JIT provides no hardware constant-time guarantee.
/// </remarks>
internal static class CanonicalScalarReduction
{
    /// <summary>The shift that propagates a signed 32-bit difference's sign through every bit.</summary>
    private const int SignBitShift = 31;


    /// <summary>
    /// Reduces <paramref name="value"/> into <c>[0, modulus)</c> by one conditional subtraction.
    /// The value must be below twice the nonzero modulus, and all three spans must have equal lengths.
    /// </summary>
    /// <param name="value">The original unsigned big-endian value; may overlap the destination.</param>
    /// <param name="modulus">The nonzero big-endian modulus; must not partially overlap the destination.</param>
    /// <param name="destination">Receives the difference or original value by constant-time mask selection.</param>
    /// <exception cref="ArgumentException">When the span lengths differ.</exception>
    internal static void ReduceOnce(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        ReduceOnceCore(value, modulus, destination);
    }


    /// <summary>
    /// Reduces <paramref name="value"/> in place into <c>[0, modulus)</c> by one conditional subtraction.
    /// The value must be below twice the nonzero modulus, and both spans must have equal lengths.
    /// </summary>
    /// <param name="value">The unsigned big-endian value, overwritten with its reduction.</param>
    /// <param name="modulus">The nonzero big-endian modulus; must not partially overlap the value.</param>
    /// <exception cref="ArgumentException">When the span lengths differ.</exception>
    internal static void ReduceOnceInPlace(Span<byte> value, ReadOnlySpan<byte> modulus)
    {
        ReduceOnceCore(value, modulus, value);
    }


    /// <summary>
    /// Subtracts equal-length unsigned big-endian operands in place without data-dependent branches.
    /// Underflow wraps at the span's byte width and is reported through the final borrow.
    /// </summary>
    /// <param name="minuend">The unsigned big-endian value, overwritten with the difference.</param>
    /// <param name="subtrahend">The unsigned big-endian value to subtract; may exactly alias but must not partially overlap the minuend.</param>
    /// <returns>Zero when the original minuend is at least the subtrahend; one otherwise.</returns>
    /// <exception cref="ArgumentException">When the span lengths differ.</exception>
    internal static int SubtractInPlace(Span<byte> minuend, ReadOnlySpan<byte> subtrahend)
    {
        if(minuend.Length != subtrahend.Length)
        {
            throw new ArgumentException("The operands must have equal byte lengths.", nameof(subtrahend));
        }

        return SubtractCore(minuend, subtrahend, minuend);
    }


    /// <summary>
    /// Validates the widths, subtracts once, and selects the original value exactly when subtraction borrows.
    /// </summary>
    /// <param name="value">The unsigned big-endian value below twice the nonzero modulus.</param>
    /// <param name="modulus">The nonzero big-endian modulus.</param>
    /// <param name="destination">Receives the canonical reduction.</param>
    /// <exception cref="ArgumentException">When the span lengths differ.</exception>
    private static void ReduceOnceCore(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus, Span<byte> destination)
    {
        if(value.Length != modulus.Length)
        {
            throw new ArgumentException("The value and modulus must have equal byte lengths.", nameof(modulus));
        }

        if(value.Length != destination.Length)
        {
            throw new ArgumentException("The value and destination must have equal byte lengths.", nameof(destination));
        }

        //The saved input remains available for selection even when the destination overlaps it.
        Span<byte> original = stackalloc byte[value.Length];
        value.CopyTo(original);
        int borrow = SubtractCore(original, modulus, destination);
        int keepOriginalMask = -borrow;
        for(int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)((destination[i] & ~keepOriginalMask) | (original[i] & keepOriginalMask));
        }

        CryptographicOperations.ZeroMemory(original);
    }


    /// <summary>Writes the fixed-width difference of equal-length operands and returns the final borrow.</summary>
    /// <param name="minuend">The unsigned big-endian value to subtract from.</param>
    /// <param name="subtrahend">The unsigned big-endian value to subtract.</param>
    /// <param name="destination">Receives the difference; may exactly alias either operand.</param>
    /// <returns>The final borrow, zero or one.</returns>
    private static int SubtractCore(ReadOnlySpan<byte> minuend, ReadOnlySpan<byte> subtrahend, Span<byte> destination)
    {
        int borrow = 0;
        for(int i = minuend.Length - 1; i >= 0; i--)
        {
            int difference = minuend[i] - subtrahend[i] - borrow;
            borrow = (difference >> SignBitShift) & 1;
            destination[i] = (byte)(difference & byte.MaxValue);
        }

        return borrow;
    }
}
