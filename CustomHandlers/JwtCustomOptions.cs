using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationPractice.CustomHandlers
{
    public class JwtCustomOptions : AuthenticationSchemeOptions
    {
        public  const string DefaultScheme = "JwtCustom";

		public string? TokenHeaderValue { get; set; }
		public string? SingInKey { get; set; }
		public int? DurationInMinutes { get; set; }

		public SigningCredentials SigningCredentials => GetSigningCredentials();

		private SigningCredentials GetSigningCredentials(){

				var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SingInKey));

				return new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
		}
    }
}