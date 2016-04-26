using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace OpenIdConnect.AzureAdSample
{
    public class AuthSessionTokenCache : TokenCache
    {
        private const string TokenCacheKey = ".TokenCache";

        private HttpContext _httpContext;
        private AuthenticateContext _authenticateContext;

        public AuthSessionTokenCache(HttpContext httpContext) : base()
        {
            _httpContext = httpContext;
            BeforeAccess = BeforeAccessNotification;
            AfterAccess = AfterAccessNotification;
            BeforeWrite = BeforeWriteNotification;
        }

        public string AuthenticationScheme { get; set; } = CookieAuthenticationDefaults.AuthenticationScheme;

        // Notification raised before ADAL accesses the cache.
        // This is your chance to update the in-memory copy from the DB, if the in-memory version is stale
        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            // Retrieve the auth session with the cached tokens
            _authenticateContext = new AuthenticateContext(CookieAuthenticationDefaults.AuthenticationScheme);
            _httpContext.Authentication.AuthenticateAsync(_authenticateContext).Wait();
            var authProperties = new AuthenticationProperties(_authenticateContext.Properties);

            string cachedTokensText;
            if (authProperties.Items.TryGetValue(TokenCacheKey, out cachedTokensText))
            {
                var cachedTokens = Convert.FromBase64String(cachedTokensText);
                Deserialize(cachedTokens);
            }
        }

        // Notification raised after ADAL accessed the cache.
        // If the HasStateChanged flag is set, ADAL changed the content of the cache
        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if state changed
            if (HasStateChanged)
            {
                var cachedTokens = Serialize();
                var cachedTokensText = Convert.ToBase64String(cachedTokens);
                var authProperties = new AuthenticationProperties(_authenticateContext.Properties);
                authProperties.Items[TokenCacheKey] = cachedTokensText;
                _httpContext.Authentication.SignInAsync(AuthenticationScheme, _authenticateContext.Principal, authProperties).Wait();
            }
        }

        private void BeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // if you want to ensure that no concurrent write take place, use this notification to place a lock on the entry
        }
    }
}
