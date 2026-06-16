using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="MultilinearExtension"/> that report
/// on its contents without performing arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// These predicates work exclusively against the public read-only span
/// and the canonical layout. They do not call backend delegates and
/// therefore do not depend on any backend wiring — they are safe to
/// use in debugger displays, assertions, and test helpers without
/// first composing a backend.
/// </para>
/// <para>
/// Identity tests (<see cref="MultilinearExtensionInspectionExtensions.IsZero"/>,
/// <see cref="MultilinearExtensionInspectionExtensions.IsConstant"/>)
/// walk every byte with an OR-accumulator rather than returning early
/// on the first mismatch. MLE evaluations are not secret in most
/// contexts, but the constant-time walk keeps the timing shape uniform
/// across inputs when the same code is reused on commitment- or
/// witness-derived MLEs that may carry secrets.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MultilinearExtensionInspectionExtensions
{
    extension(MultilinearExtension mle)
    {
        /// <summary>
        /// The dimensions of the MLE bundled into a single value.
        /// </summary>
        public MultilinearExtensionDimensions Dimensions
        {
            get
            {
                ArgumentNullException.ThrowIfNull(mle);

                return new MultilinearExtensionDimensions(mle.VariableCount, mle.EvaluationCount);
            }
        }


        /// <summary>
        /// Indicates whether every evaluation of the MLE is the field
        /// zero.
        /// </summary>
        /// <remarks>
        /// Walks every byte of the buffer. A canonical-form field zero
        /// is the all-zero byte pattern, so the OR-accumulator across
        /// every byte equals zero iff every evaluation is zero.
        /// </remarks>
        public bool IsZero
        {
            get
            {
                ArgumentNullException.ThrowIfNull(mle);

                ReadOnlySpan<byte> bytes = mle.AsReadOnlySpan();
                byte accumulator = 0;
                for(int i = 0; i < bytes.Length; i++)
                {
                    accumulator |= bytes[i];
                }


                return accumulator == 0;
            }
        }


        /// <summary>
        /// Indicates whether every evaluation of the MLE is the same
        /// field element.
        /// </summary>
        /// <remarks>
        /// A constant MLE represents a polynomial that takes the same
        /// value at every point of the boolean hypercube — and, by the
        /// multilinear-extension uniqueness, at every point of the
        /// embedding space too. The check compares each evaluation's
        /// bytes to the first evaluation's bytes; for canonical-form
        /// scalars (reduced into <c>[0, r)</c>) equality of bytes is
        /// equality of values.
        /// </remarks>
        public bool IsConstant
        {
            get
            {
                ArgumentNullException.ThrowIfNull(mle);

                ReadOnlySpan<byte> bytes = mle.AsReadOnlySpan();
                int elementSize = mle.FieldElementSizeBytes;
                if(bytes.Length <= elementSize)
                {
                    //One evaluation (or zero) is trivially constant.
                    return true;
                }

                ReadOnlySpan<byte> head = bytes[..elementSize];
                byte accumulator = 0;
                for(int offset = elementSize; offset < bytes.Length; offset += elementSize)
                {
                    ReadOnlySpan<byte> slot = bytes.Slice(offset, elementSize);
                    for(int j = 0; j < elementSize; j++)
                    {
                        accumulator |= (byte)(slot[j] ^ head[j]);
                    }
                }


                return accumulator == 0;
            }
        }
    }
}