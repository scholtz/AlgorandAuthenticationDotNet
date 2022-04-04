using Microsoft.AspNetCore.Authentication;
using System;

namespace AlgorandAuthentication
{
    public static class Extensions
    {
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder)
            => builder.AddAlgorand(AlgorandAuthenticationHandler.ID, _ => { });
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder, Action<AlgorandAuthenticationOptions> configureOptions)
            => builder.AddScheme<AlgorandAuthenticationOptions, AlgorandAuthenticationHandler>(AlgorandAuthenticationHandler.ID, AlgorandAuthenticationHandler.ID, configureOptions);
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder, string authenticationScheme, Action<AlgorandAuthenticationOptions> configureOptions)
            => builder.AddScheme<AlgorandAuthenticationOptions, AlgorandAuthenticationHandler>(authenticationScheme, authenticationScheme, configureOptions);
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<AlgorandAuthenticationOptions> configureOptions)
            => builder.AddScheme<AlgorandAuthenticationOptions, AlgorandAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}
