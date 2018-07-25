using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(SocialNetwork.Web.Startup))]

namespace SocialNetwork.Web
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = "socialnetwork_implicit",
                Authority = ConfigurationManager.AppSettings["Authority"],
                RedirectUri = $"{ConfigurationManager.AppSettings["RedirectUri"]}/private",
                ResponseType = "id_token",
                Scope = "openid profile",

                UseTokenLifetime = false,
                SignInAsAuthenticationType = "Cookies",
                PostLogoutRedirectUri = ConfigurationManager.AppSettings["RedirectUri"],
                
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = notification =>
                    {
                        var identity = notification.AuthenticationTicket.Identity;

                        identity.AddClaim(new Claim("id_token", notification.ProtocolMessage.IdToken));

                        notification.AuthenticationTicket = new AuthenticationTicket(identity, notification.AuthenticationTicket.Properties);

                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = notification =>
                    {
                        if (notification.ProtocolMessage.RequestType != OpenIdConnectRequestType.LogoutRequest)
                        {
                            return Task.FromResult(0);
                        }

                        var idTokenHint = notification.OwinContext.Authentication.User.FindFirst("id_token");

                        if (idTokenHint != null)
                        {
                            notification.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                        }

                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}
