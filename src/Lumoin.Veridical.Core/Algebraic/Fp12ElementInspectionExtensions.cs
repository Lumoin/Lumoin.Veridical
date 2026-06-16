using Lumoin.Veridical.Core;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Fp12Element"/> that
/// report on its contents without performing arithmetic.
/// </summary>
/// <remarks>
/// Predicates work exclusively against the canonical byte layout
/// exposed through the public read-only span.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Fp12ElementInspectionExtensions
{
    extension(Fp12Element element)
    {
        /// <summary>
        /// Indicates whether both Fp6 components are the field zero,
        /// i.e. the additive identity of Fp12.
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
        /// Indicates whether the element is the multiplicative identity
        /// <c>(1, 0)</c>: the Fp6 one in the constant-term slot and zero
        /// in the <c>w</c>-coefficient.
        /// </summary>
        public bool IsOne
        {
            get
            {
                ArgumentNullException.ThrowIfNull(element);
                ReadOnlySpan<byte> bytes = element.AsReadOnlySpan();
                int onePosition = WellKnownCurves.GetBaseFieldSizeBytes(element.Curve) - 1;
                if(bytes[onePosition] != 0x01)
                {
                    return false;
                }
                for(int i = 0; i < bytes.Length; i++)
                {
                    if(i == onePosition)
                    {
                        continue;
                    }
                    if(bytes[i] != 0)
                    {
                        return false;
                    }
                }


                return true;
            }
        }


        /// <summary>
        /// Returns a lowercase hexadecimal representation of the full
        /// 576-byte canonical encoding (<c>c0</c> followed by <c>c1</c>).
        /// </summary>
        public string ToHexString()
        {
            ArgumentNullException.ThrowIfNull(element);

            return Convert.ToHexStringLower(element.AsReadOnlySpan());
        }
    }
}