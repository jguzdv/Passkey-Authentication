using System;
using System.Text;

namespace JGUZDV.ADFS.PasskeyAuthenticationAdapter
{
    /// <summary>
    /// Helper class to handle Base64Url. Based on Carbon.Jose source code.
    /// </summary>
    public static class Base64Url
    {
        /// <summary>
        /// Converts arg data to a Base64Url encoded string.
        /// </summary>
        public static string Encode(byte[] arg)
        {
            var base64 = Convert.ToBase64String(arg);

            var base64Url = new StringBuilder(base64.Length);
            for(int i = 0; i < base64.Length; i++)
            {
                switch(base64[i])
                {
                    case '+':
                        base64Url.Append('-');
                        break;
                    case '/':
                        base64Url.Append('_');
                        break;
                    case '=':
                        break;
                    default:
                        base64Url.Append(base64[i]);
                        break;
                }
            }

            return base64Url.ToString();
        }

        ///// <summary>
        ///// Decodes a Base64Url encoded string to its raw bytes.
        ///// </summary>
        //public static byte[] Decode(ReadOnlySpan<char> text)
        //{
        //    int padCharCount = (text.Length % 4) switch
        //    {
        //        2 => 2,
        //        3 => 1,
        //        _ => 0
        //    };

        //    int encodedLength = text.Length + padCharCount;

        //    char[] buffer = ArrayPool<char>.Shared.Rent(encodedLength);

        //    text.CopyTo(buffer);

        //    for (int i = 0; i < text.Length; i++)
        //    {
        //        ref char c = ref buffer[i];

        //        switch (c)
        //        {
        //            case '-':
        //                c = '+';
        //                break;
        //            case '_':
        //                c = '/';
        //                break;
        //        }
        //    }

        //    if (padCharCount == 1)
        //    {
        //        buffer[encodedLength - 1] = '=';
        //    }
        //    else if (padCharCount == 2)
        //    {
        //        buffer[encodedLength - 1] = '=';
        //        buffer[encodedLength - 2] = '=';
        //    }

        //    var result = Convert.FromBase64CharArray(buffer, 0, encodedLength);

        //    ArrayPool<char>.Shared.Return(buffer, true);

        //    return result;
        //}


        ///// <summary>
        ///// Decodes a Base64Url encoded string to its raw bytes.
        ///// </summary>
        //public static byte[] DecodeUtf8(ReadOnlySpan<byte> text)
        //{
        //    int padCharCount = (text.Length % 4) switch
        //    {
        //        2 => 2,
        //        3 => 1,
        //        _ => 0
        //    };

        //    int encodedLength = text.Length + padCharCount;

        //    byte[] buffer = ArrayPool<byte>.Shared.Rent(encodedLength);

        //    text.CopyTo(buffer);

        //    for (int i = 0; i < text.Length; i++)
        //    {
        //        ref byte c = ref buffer[i];

        //        switch ((char)c)
        //        {
        //            case '-':
        //                c = (byte)'+';
        //                break;
        //            case '_':
        //                c = (byte)'/';
        //                break;
        //        }
        //    }

        //    if (padCharCount == 1)
        //    {
        //        buffer[encodedLength - 1] = (byte)'=';
        //    }
        //    else if (padCharCount == 2)
        //    {
        //        buffer[encodedLength - 1] = (byte)'=';
        //        buffer[encodedLength - 2] = (byte)'=';
        //    }

        //    if (OperationStatus.Done != Base64.DecodeFromUtf8InPlace(buffer.AsSpan(0, encodedLength), out int decodedLength))
        //    {
        //        throw new FormatException("The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.");
        //    }

        //    var result = buffer.AsSpan(0, decodedLength).ToArray();

        //    ArrayPool<byte>.Shared.Return(buffer, true);

        //    return result;
        //}
    }

}
