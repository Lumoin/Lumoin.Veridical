using Lumoin.Veridical.Core;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="G1Point"/> that report on its contents
/// without performing arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// These predicates work exclusively against the canonical compressed byte
/// layout exposed through the public read-only span. They do not call backend
/// delegates and therefore do not depend on any backend wiring — they are safe
/// to use in debugger displays, assertions, and test helpers without first
/// composing a backend.
/// </para>
/// <para>
/// The identity check is byte-equality against the curve's canonical identity
/// encoding (looked up from <see cref="WellKnownCurves"/>). This keeps the
/// wrapper agnostic to any per-curve high-byte flag layout — the wrapper never
/// interprets the compression / infinity / parity bits, which differ across
/// curves; it only compares against the one canonical identity encoding the
/// curve defines.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class G1PointInspectionExtensions
{
    extension(G1Point point)
    {
        /// <summary>
        /// Indicates whether the point is the additive identity of the group
        /// (the point at infinity), by comparing its bytes to the curve's
        /// canonical identity encoding.
        /// </summary>
        public bool IsIdentity
        {
            get
            {
                ArgumentNullException.ThrowIfNull(point);

                return point.AsReadOnlySpan().SequenceEqual(WellKnownCurves.GetG1IdentityCompressed(point.Curve));
            }
        }


        /// <summary>
        /// Returns a lowercase hexadecimal representation of the canonical
        /// compressed bytes.
        /// </summary>
        /// <remarks>
        /// Intended for debugger displays and test diagnostics. Not a
        /// wire-format encoder — that role belongs to
        /// <c>Lumoin.Veridical.Json</c> and <c>Lumoin.Veridical.Cbor</c>
        /// when those projects are introduced.
        /// </remarks>
        public string ToHexString()
        {
            ArgumentNullException.ThrowIfNull(point);

            return Convert.ToHexStringLower(point.AsReadOnlySpan());
        }
    }
}