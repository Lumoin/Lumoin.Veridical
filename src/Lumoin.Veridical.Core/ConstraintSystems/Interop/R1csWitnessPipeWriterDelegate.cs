using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Writes an R1CS witness to a pipe in the specified wire format.
/// Declaration-only in this batch; the writer-side direction lands
/// in future batches.
/// </summary>
/// <param name="pipe">The pipe accepting the encoded bytes.</param>
/// <param name="witness">The witness to serialise.</param>
/// <param name="format">The wire format identifier.</param>
/// <param name="cancellationToken">Cancellation for the write loop.</param>
public delegate ValueTask R1csWitnessPipeWriterDelegate(
    PipeWriter pipe,
    RawR1csWitness witness,
    WellKnownR1csFormatLabel format,
    CancellationToken cancellationToken);