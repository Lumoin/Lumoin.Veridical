using Lumoin.Veridical.Core;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="G2Point"/> that report on its contents
/// without performing arithmetic. Parallel to
/// <see cref="G1PointInspectionExtensions"/>: the identity check is
/// byte-equality against the curve's canonical G2 identity encoding, keeping
/// the wrapper agnostic to any per-curve flag layout.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class G2PointInspectionExtensions
{
    extension(G2Point point)
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

                return point.AsReadOnlySpan().SequenceEqual(WellKnownCurves.GetG2IdentityCompressed(point.Curve));
            }
        }


        /// <summary>
        /// Returns a lowercase hexadecimal representation of the canonical
        /// compressed bytes.
        /// </summary>
        /// <remarks>
        /// Intended for debugger displays and test diagnostics. Not a
        /// wire-format encoder.
        /// </remarks>
        public string ToHexString()
        {
            ArgumentNullException.ThrowIfNull(point);

            return Convert.ToHexStringLower(point.AsReadOnlySpan());
        }
    }
}