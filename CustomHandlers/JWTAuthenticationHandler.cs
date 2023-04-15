using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationPractice.CustomHandlers
{
	public class JWTAuthenticationHandler : AuthenticationHandler<JwtCustomOptions>
	{
		private readonly JwtSecurityTokenHandler tokenHandler;
		public JWTAuthenticationHandler(JwtSecurityTokenHandler tokenHandler, IOptionsMonitor<JwtCustomOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
		{
			this.tokenHandler = tokenHandler;

		}

		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			string authorizationHeader = Request.Headers["Authorization"];

			if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
			{
				return AuthenticateResult.Fail("Missing or invalid bearer token");
			}

			string token = authorizationHeader.Substring("Bearer".Length).Trim();

			var validationParameters = new TokenValidationParameters{
				ValidateIssuer = false,
				IssuerSigningKey = Options.SigningCredentials.Key,
				ValidateIssuerSigningKey = true,
				ValidateAudience = false
			};

			// Authenticate token using the tokenhandler
			//var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);


			//en un escenario real se usa el principal que retorna el tokenHandler
			var identity = new ClaimsIdentity(new []{new Claim(ClaimTypes.NameIdentifier, "Gerald")}, Scheme.Name);
			var principal = new ClaimsPrincipal(identity);

			var authenticationTicket = new AuthenticationTicket(principal, Scheme.Name);
			return AuthenticateResult.Success(authenticationTicket);
		}

		protected override Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			Response.StatusCode = 401;
			Response.Headers["WWW-Authenticate"] = $"Bearer realm=\"{Options.ClaimsIssuer}\", charset=\"UTF-8\"";
			return Task.CompletedTask;
		}

		protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			Response.StatusCode = 403;
			return Task.CompletedTask;
		}

	}
}