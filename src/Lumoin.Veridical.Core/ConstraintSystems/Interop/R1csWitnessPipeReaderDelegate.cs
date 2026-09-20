using Lumoin.Veridical.Core.Memory;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Reads an R1CS witness from a pipe in the specified wire format.
/// Parallel to <see cref="R1csPipeReaderDelegate"/> for the
/// witness-side artifact; the two delegates are split rather than
/// unified by a generic because <see cref="RawR1csInstance"/> and
/// <see cref="RawR1csWitness"/> are distinct deliverables and the
/// concrete reader signatures are easier to use without type-
/// parameter ceremony.
/// </summary>
/// <param name="pipe">The pipe carrying the binary file's bytes.</param>
/// <param name="format">
/// The wire format identifier; concrete readers validate against
/// the format they support.
/// </param>
/// <param name="curve">
/// The curve whose scalar field the witness elements live in. Readers
/// reject mismatched fields with <see cref="R1csUnsupportedFieldException"/>.
/// </param>
/// <param name="pool">The pool the resulting witness's buffer is rented from.</param>
/// <param name="maximumIntakeBytes">
/// The largest number of bytes the reader admits from
/// <paramref name="pipe"/> before rejecting the input with
/// <see cref="R1csIntakeLimitExceededException"/>, checked as bytes
/// accumulate rather than once the whole stream has arrived.
/// <see cref="WellKnownR1csIntakeLimits.Unbounded"/> imposes no
/// ceiling beyond the runtime's own addressable limit; a caller
/// parsing untrusted input states a real budget instead.
/// </param>
/// <param name="cancellationToken">Cancellation for the read loop.</param>
/// <returns>The constructed <see cref="RawR1csWitness"/>.</returns>
public delegate RawR1csWitness R1csWitnessPipeReaderDelegate(
    PipeReader pipe,
    WellKnownR1csFormatLabel format,
    CurveParameterSet curve,
    BaseMemoryPool pool,
    long maximumIntakeBytes,
    CancellationToken cancellationToken);