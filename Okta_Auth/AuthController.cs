using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Authentication;
using Okta_Auth.Identity;
using Microsoft.AspNetCore.Cors;
using System.Text.Json;
using System.Security.Claims;
using ITfoxtec.Identity.Saml2.Claims;
using Okta_Auth.Pages;
using System.Net;
using System.IO;

namespace Okta_Auth.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    [EnableCors("CorsPolicy")]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect("https://localhost:3000/login");
        }

        [Route("whoami")]
        public async Task<IActionResult> WhoAmI()
        {
            //User.Identity
            //JsonSerializer.Serialize(

            WebRequest request = WebRequest.Create($"https://dev-98677186.okta.com/api/v1/users/{User.Identity.Name}");

            request.Headers.Add("Authorization", "SSWS 006y2BxwmonOCq0DppI_J6NUD9f01e6XZj8LYIFCBy");
            request.ContentType = "application/json; charset=utf-8";

            var response = await request.GetResponseAsync();

            using var reader = new StreamReader(response.GetResponseStream());

            var data = reader.ReadToEnd(); 

            if (User.Identity.IsAuthenticated) return Ok(data);
            else return Unauthorized("PASHEL NAHUI");
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            return Redirect("~/");
        }
    }
}
