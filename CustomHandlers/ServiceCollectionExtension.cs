namespace AuthenticationPractice.CustomHandlers
{
    public static class ServiceCollectionExtension
    {
        public static IServiceCollection AddCustomJWTAuthentication(this IServiceCollection services, IConfiguration configuration){
			services.AddAuthentication(JwtCustomOptions.DefaultScheme)
			.AddScheme<JwtCustomOptions, JWTAuthenticationHandler>(JwtCustomOptions.DefaultScheme, options =>
			{
				options.SingInKey = configuration.GetValue<string>("JwtOptions:Key");
				options.DurationInMinutes = configuration.GetValue<int>("JwtOptions:DurationInMinutes");
			});

			return services;
		}
    }
}