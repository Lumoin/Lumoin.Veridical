using Lumoin.Veridical.Core;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Fp2Element"/> that
/// report on its contents without performing arithmetic.
/// </summary>
/// <remarks>
/// Predicates work exclusively against the canonical byte layout
/// exposed through the public read-only span. They do not call backend
/// delegates and therefore are safe to use in debugger displays,
/// assertions, and test helpers without first composing a backend.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Fp2ElementInspectionExtensions
{
    extension(Fp2Element element)
    {
        /// <summary>
        /// Indicates whether both components <c>c0</c> and <c>c1</c> are
        /// the field zero, i.e. the additive identity of Fp2.
        /// </summary>
        public bool IsZero
        {
            get
            {
                ArgumentNullException.ThrowIfNull(element);
                ReadOnlySpan<byte> bytes = element.AsReadOnlySpan();
                for(int i = 0; i < bytes.Length; i++)
                {
                    if(bytes[i] != 0)
                    {
                        return false;
                    }
                }


                return true;
            }
        }


        /// <summary>
        /// Indicates whether the element represents <c>(1, 0)</c>, the
        /// multiplicative identity of Fp2.
        /// </summary>
        public bool IsOne
        {
            get
            {
                ArgumentNullException.ThrowIfNull(element);
                ReadOnlySpan<byte> c0 = element.GetRealComponentBytes();
                ReadOnlySpan<byte> c1 = element.GetImaginaryComponentBytes();

                if(c0[^1] != 0x01)
                {
                    return false;
                }
                for(int i = 0; i < c0.Length - 1; i++)
                {
                    if(c0[i] != 0)
                    {
                        return false;
                    }
                }
                for(int i = 0; i < c1.Length; i++)
                {
                    if(c1[i] != 0)
                    {
                        return false;
                    }
                }


                return true;
            }
        }


        /// <summary>
        /// Returns a lowercase hexadecimal representation of the full
        /// 96-byte canonical encoding (<c>c0</c> followed by <c>c1</c>).
        /// </summary>
        public string ToHexString()
        {
            ArgumentNullException.ThrowIfNull(element);

            return Convert.ToHexStringLower(element.AsReadOnlySpan());
        }
    }
}