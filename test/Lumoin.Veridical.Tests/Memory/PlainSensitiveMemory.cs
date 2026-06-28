using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Memory;

/// <summary>
/// A minimal <see cref="SensitiveMemory"/> leaf used to exercise the base
/// class lifetime contract without involving curve semantics.
/// </summary>
internal sealed class PlainSensitiveMemory: SensitiveMemory
{
    public PlainSensitiveMemory(IMemoryOwner<byte> owner)
        : base(owner, Tag.Empty)
    {
    }
}
