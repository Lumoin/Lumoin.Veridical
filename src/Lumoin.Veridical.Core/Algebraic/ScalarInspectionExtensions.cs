using Lumoin.Veridical.Core;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Scalar"/> that report on its contents
/// without performing arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// These predicates work exclusively against the public read-only span and
/// the canonical big-endian byte layout. They do not call backend delegates
/// and therefore do not depend on any backend wiring — they are safe to use
/// in debugger displays, assertions, and test helpers without first composing
/// a backend.
/// </para>
/// <para>
/// Identity tests (<c>IsZero</c>, <c>IsOne</c>) walk every byte rather than
/// returning early on the first mismatch. Field elements are not secret in
/// most contexts, but the constant-time walk avoids leaking the high-byte
/// pattern through a microarchitectural side channel when the same code is
/// reused on secret material such as a private key encoded as a scalar.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class ScalarInspectionExtensions
{
    extension(Scalar scalar)
    {
        /// <summary>
        /// Indicates whether the scalar is the zero element of the field.
        /// </summary>
        /// <remarks>
        /// All bytes are zero in the canonical big-endian layout; the value
        /// is also unique because canonical scalars are reduced modulo the
        /// field order, so the additive identity has exactly one byte
        /// representation.
        /// </remarks>
        public bool IsZero
        {
            get
            {
                ArgumentNullException.ThrowIfNull(scalar);
                ReadOnlySpan<byte> bytes = scalar.AsReadOnlySpan();
                byte accumulator = 0;
                for(int i = 0; i < bytes.Length; i++)
                {
                    accumulator |= bytes[i];
                }


                return accumulator == 0;
            }
        }


        /// <summary>
        /// Indicates whether the scalar is the multiplicative identity (one).
        /// </summary>
        /// <remarks>
        /// Big-endian one is <c>0x00..00 0x01</c>: thirty-one leading zero
        /// bytes followed by a final byte of <c>0x01</c>. As with
        /// <see cref="IsZero"/>, the test walks every byte to keep timing
        /// uniform across inputs.
        /// </remarks>
        public bool IsOne
        {
            get
            {
                ArgumentNullException.ThrowIfNull(scalar);
                ReadOnlySpan<byte> bytes = scalar.AsReadOnlySpan();
                byte leadingAccumulator = 0;
                for(int i = 0; i < bytes.Length - 1; i++)
                {
                    leadingAccumulator |= bytes[i];
                }


                return leadingAccumulator == 0 && bytes[^1] == 1;
            }
        }


        /// <summary>
        /// Returns a lowercase hexadecimal representation of the scalar bytes
        /// in their canonical big-endian order.
        /// </summary>
        /// <remarks>
        /// Intended for debugger displays and test diagnostics. Not a
        /// wire-format encoder — that role belongs to
        /// <c>Lumoin.Veridical.Json</c> and <c>Lumoin.Veridical.Cbor</c> when
        /// those projects are introduced.
        /// </remarks>
        public string ToHexString()
        {
            ArgumentNullException.ThrowIfNull(scalar);

            return Convert.ToHexStringLower(scalar.AsReadOnlySpan());
        }
    }
}