using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Writes an R1CS instance to a pipe in the specified wire format.
/// Declared in this batch as part of the adapter surface so the
/// public API visibly accommodates the writer direction; no
/// implementation is wired in this batch — writers land in future
/// batches alongside their corresponding readers.
/// </summary>
/// <param name="pipe">The pipe accepting the encoded bytes.</param>
/// <param name="instance">The instance to serialise.</param>
/// <param name="format">The wire format identifier; implementations validate against the format they emit.</param>
/// <param name="cancellationToken">Cancellation for the write loop.</param>
public delegate ValueTask R1csPipeWriterDelegate(
    PipeWriter pipe,
    RawR1csInstance instance,
    WellKnownR1csFormatLabel format,
    CancellationToken cancellationToken);