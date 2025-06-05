using System.Security.Claims;
using System.Security.Cryptography;

using JGUZDV.Passkey.ActiveDirectory;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace JGUZDV.PasskeyAuth.Authentication;

public class OneTimePasswordHandler
{
    private const string DataProtectionPurpose = "OneTimePassword";

    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly IDistributedCache _distributedCache;

    private static readonly DistributedCacheEntryOptions _cacheEntryOptions = new() { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(2) };

    public OneTimePasswordHandler(
        IDataProtectionProvider dataProtectionProvider,
        IDistributedCache distributedCache
        )
    {
        _dataProtectionProvider = dataProtectionProvider;
        _distributedCache = distributedCache;
    }

    internal async Task<string> CreateOneTimePasswordAsync(HttpContext context, ClaimsIdentity identity, CancellationToken ct)
    {
        var password = new Guid(RandomNumberGenerator.GetBytes(16)).ToString("N");
        var ipAddress = context.Connection.RemoteIpAddress!.ToString();

        var claims = identity.Claims.Select(x => new JsonClaim(x.Type, x.Value)).ToArray();
        var jsonClaims = System.Text.Json.JsonSerializer.Serialize(claims);

        var protectedJson = _dataProtectionProvider.CreateProtector(DataProtectionPurpose).Protect(jsonClaims);
        await _distributedCache.SetStringAsync(
            $"{password}_{ipAddress}",
            protectedJson,
            _cacheEntryOptions,
            ct);

        return password;
    }


    internal async Task<(ClaimsIdentity? identity, IResult? errorResult)> GetIdentityFromPassword(string password, HttpContext context)
    {
        var ipAddress = context.Connection.RemoteIpAddress!.ToString();
        var protectedJson = await _distributedCache.GetStringAsync($"{password}_{ipAddress}");

        //Remove the data from the cache, so it can only be used once.
        await _distributedCache.RemoveAsync($"{password}_{ipAddress}");

        if(protectedJson == null)
        {
            return (null, Results.BadRequest("OneTimePassword:InvalidOrExpiredOrWrongIp"));
        }

        var jsonClaims = _dataProtectionProvider.CreateProtector(DataProtectionPurpose).Unprotect(protectedJson);
        if (jsonClaims == null)
        {
            return (null, Results.BadRequest("OneTimePassword:InvalidOrExpiredOrWrongIp"));
        }

        var claims = System.Text.Json.JsonSerializer.Deserialize<JsonClaim[]>(jsonClaims);
        var identity = new ClaimsIdentity(
            claims?.Select(x => new Claim(x.Type, x.Value)) ?? [],
            "OneTimePassword",
            "sub",
            "role"
        );

        return (identity, null);
    }


    private record JsonClaim(string Type, string Value);
}
