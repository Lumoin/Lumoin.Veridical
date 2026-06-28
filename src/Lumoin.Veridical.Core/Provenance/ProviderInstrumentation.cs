using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Provenance;

/// <summary>
/// Helpers for stamping provenance information onto tagged values and
/// OpenTelemetry activities.
/// </summary>
/// <remarks>
/// <para>
/// Backends call <see cref="StampTag"/> to add the four provenance dimensions
/// (<see cref="ProviderLibrary"/>, <see cref="CryptoLibrary"/>,
/// <see cref="ProviderClass"/>, <see cref="ProviderOperation"/>) to the
/// <see cref="Tag"/> that travels with a produced value. They call
/// <see cref="SetProviderAttributes"/> to stamp the same four dimensions as
/// activity tags on the OTel <see cref="Activity"/> spanning the value's
/// lifetime.
/// </para>
/// <para>
/// The two methods do not allocate when no listener is attached: the activity
/// passed in is <see langword="null"/> in that case (because
/// <see cref="ActivitySource.StartActivity(string, ActivityKind)"/> returns
/// <see langword="null"/> when no listener subscribes), and
/// <see cref="SetProviderAttributes"/> short-circuits accordingly.
/// </para>
/// <para>
/// The cost model: per produced value, one <see cref="Tag.With"/> call that
/// allocates a new <see cref="System.Collections.Frozen.FrozenDictionary{TKey, TValue}"/>
/// containing the previous entries plus four new ones. The four
/// <see cref="ProviderLibrary"/>, <see cref="CryptoLibrary"/>,
/// <see cref="ProviderClass"/>, <see cref="ProviderOperation"/> instances
/// themselves are typically resolved once per backend class and cached as
/// <c>private static readonly</c> fields, so the only per-call allocation is
/// the <see cref="ProviderOperation"/> when it is constructed inline rather
/// than cached.
/// </para>
/// </remarks>
public static class ProviderInstrumentation
{
    /// <summary>
    /// Returns a new tag that contains all entries from <paramref name="tag"/>
    /// plus the four provenance entries identifying the producer.
    /// </summary>
    /// <param name="tag">The inbound tag to extend.</param>
    /// <param name="providerLibrary">The wrapping assembly that produced the value.</param>
    /// <param name="cryptoLibrary">The underlying cryptographic library used.</param>
    /// <param name="providerClass">The static class within the wrapping assembly.</param>
    /// <param name="providerOperation">The specific method that produced the value.</param>
    /// <returns>A new <see cref="Tag"/> with the four provenance entries added or replaced.</returns>
    public static Tag StampTag(
        Tag tag,
        ProviderLibrary providerLibrary,
        CryptoLibrary cryptoLibrary,
        ProviderClass providerClass,
        ProviderOperation providerOperation)
    {
        ArgumentNullException.ThrowIfNull(tag);

        return tag.With(providerLibrary)
            .With(cryptoLibrary)
            .With(providerClass)
            .With(providerOperation);
    }


    /// <summary>
    /// Sets the four provenance dimensions as activity tags on the supplied
    /// OpenTelemetry activity.
    /// </summary>
    /// <param name="activity">
    /// The activity to stamp, or <see langword="null"/> if no OTel listener is
    /// attached. When <see langword="null"/>, this method is a no-op.
    /// </param>
    /// <param name="providerLibrary">The wrapping assembly that produced the value.</param>
    /// <param name="cryptoLibrary">The underlying cryptographic library used.</param>
    /// <param name="providerClass">The static class within the wrapping assembly.</param>
    /// <param name="providerOperation">The specific method that produced the value.</param>
    public static void SetProviderAttributes(
        Activity? activity,
        ProviderLibrary providerLibrary,
        CryptoLibrary cryptoLibrary,
        ProviderClass providerClass,
        ProviderOperation providerOperation)
    {
        if(activity is null)
        {
            return;
        }

        activity.SetTag(CryptoTelemetry.ProviderLibrary, providerLibrary.Name);
        activity.SetTag(CryptoTelemetry.ProviderLibraryVersion, providerLibrary.Version);
        activity.SetTag(CryptoTelemetry.LibraryName, cryptoLibrary.Name);
        activity.SetTag(CryptoTelemetry.LibraryVersion, cryptoLibrary.Version);
        activity.SetTag(CryptoTelemetry.ProviderClass, providerClass.Name);
        activity.SetTag(CryptoTelemetry.ProviderOperation, providerOperation.Name);
    }
}