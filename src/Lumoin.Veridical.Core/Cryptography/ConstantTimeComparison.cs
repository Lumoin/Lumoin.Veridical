using System;

namespace Lumoin.Veridical.Core.Cryptography;

/// <summary>
/// Branchless, data-independent comparisons over canonical big-endian scalars — the constant-time primitives
/// the ECDSA / SECDSA range checks and the RFC 6979 nonce loop share. Both walk the full operand width with no
/// data-dependent early return, so neither leaks, by where it stops, the position of the first differing byte
/// of a secret operand (a private key, a proof witness, or a candidate nonce). This is best-effort in managed
/// code — the JIT may re-introduce a branch and there is no hardware constant-time guarantee — and it is also
/// the cheap part: the dominant variable-time cost in a sign or a proof is the injected mod-<c>n</c>
/// arithmetic, not this comparison. Held as one <see langword="internal"/> primitive so a future hardening of
/// the comparison (or a switch to an unsigned-mask formulation) lands in exactly one place rather than
/// silently diverging across the call sites; internal, so the best-effort caveat is never offered to an
/// external caller as a hard guarantee.
/// </summary>
internal static class ConstantTimeComparison
{
    /// <summary>
    /// Whether every byte of <paramref name="value"/> is zero. OR-accumulates the whole span (no early exit),
    /// so it does not reveal where the first non-zero byte of a secret operand sits.
    /// </summary>
    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        int accumulator = 0;
        for(int i = 0; i < value.Length; i++)
        {
            accumulator |= value[i];
        }

        return accumulator == 0;
    }


    /// <summary>
    /// Whether <paramref name="a"/> &lt; <paramref name="b"/> as equal-length canonical big-endian scalars:
    /// subtract b from a across the full width and read the final borrow-out, which is 1 exactly when a &lt; b.
    /// Every byte is processed (no data-dependent early return), so it does not leak where the operands first
    /// differ. The operands must be the same length.
    /// </summary>
    internal static bool IsLess(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        int borrow = 0;
        for(int i = a.Length - 1; i >= 0; i--)
        {
            int difference = a[i] - b[i] - borrow;
            borrow = (difference >> 31) & 1;   //1 when the running subtraction went negative
        }

        return borrow == 1;
    }
}
