using System.DirectoryServices;
using System.Runtime.Versioning;

namespace JGUZDV.Extensions.ActiveDirectory;

public static class LargeIntegerHelper
{
    [SupportedOSPlatform("windows")]
    public static void SetLargeInteger(this PropertyValueCollection propertyValueCollection, long value)
    {
        var largeIntegerValue = new ActiveDs.LargeInteger();
        largeIntegerValue.HighPart = (int)(value >> 32);
        largeIntegerValue.LowPart = (int)(value & 0xFFFFFFFF);

        propertyValueCollection.Value = largeIntegerValue;
    }


    [SupportedOSPlatform("windows")]
    public static long? GetLargeInteger(this PropertyValueCollection propertyValueCollection)
    {
        if (propertyValueCollection.Value is null)
        {
            return null;
        }

        var largeIntegerValue = (ActiveDs.LargeInteger)propertyValueCollection.Value;
        return ((long)largeIntegerValue.HighPart << 32) | (uint)largeIntegerValue.LowPart;
    }
}
