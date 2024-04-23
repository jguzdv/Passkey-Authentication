using System;
using System.Globalization;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter
{
    internal class Utility
    {
        public static CultureInfo GetCultureInfoFromLcid(int lcid)
        {
            try
            {
                return CultureInfo.GetCultureInfo(lcid);
            }
            catch
            {
                return CultureInfo.CurrentCulture;
            }
        }

        internal static string GetStringResource(string resourceName, int lcid)
        {
            if (string.IsNullOrEmpty(resourceName))
            {
                throw new ArgumentNullException("resourceName");
            }
            return Resources.ResourceManager.GetString(resourceName, GetCultureInfoFromLcid(lcid));
        }

    }
}
