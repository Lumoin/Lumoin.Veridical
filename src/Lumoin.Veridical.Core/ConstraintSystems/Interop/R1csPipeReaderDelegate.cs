using Lumoin.Veridical.Core.Memory;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop;

/// <summary>
/// Reads an R1CS instance from a pipe in the specified wire format.
/// Concrete implementations (for example
/// <see cref="Circom.CircomR1csReader.Reader"/>) own the per-format
/// parsing logic; the delegate shape lets application code wire in
/// any combination of supported formats without coupling to a
/// specific reader's static type.
/// </summary>
/// <param name="pipe">
/// The pipe carrying the binary file's bytes. The reader consumes
/// bytes from the pipe; the caller owns the pipe lifetime.
/// </param>
/// <param name="format">
/// The wire format the pipe is delivering. The reader implementation
/// validates that <paramref name="format"/> matches the format it
/// supports and throws <see cref="System.ArgumentException"/> on a
/// mismatch.
/// </param>
/// <param name="curve">
/// The curve identifying the scalar field the resulting instance is
/// constructed over. Readers reject files whose declared field
/// modulus does not match the curve's scalar field with
/// <see cref="R1csUnsupportedFieldException"/>.
/// </param>
/// <param name="pool">
/// The pool from which the resulting instance's pool-rented buffers
/// are taken. Intermediate parser allocations may use other pools
/// or the GC heap; the final
/// <see cref="RawR1csInstance"/> rents from <paramref name="pool"/>.
/// </param>
/// <param name="cancellationToken">
/// Cancellation for the read loop. Long-running reads of large
/// circuit files honour cancellation between sections.
/// </param>
/// <returns>
/// The fully-constructed <see cref="RawR1csInstance"/>. The instance
/// owns the matrices via the standard <c>SensitiveMemory</c> base
/// pattern; the caller is responsible for disposing it.
/// </returns>
public delegate RawR1csInstance R1csPipeReaderDelegate(
    PipeReader pipe,
    WellKnownR1csFormatLabel format,
    CurveParameterSet curve,
    SensitiveMemoryPool<byte> pool,
    CancellationToken cancellationToken);