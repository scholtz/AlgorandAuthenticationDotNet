using Microsoft.AspNetCore.Authentication;
using System;

namespace AlgorandAuthenticationV2
{
    public static class ExtensionsV2
    {
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder)
            => builder.AddAlgorand(AlgorandAuthenticationHandlerV2.ID, _ => { });
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder, Action<AlgorandAuthenticationOptionsV2> configureOptions)
            => builder.AddScheme<AlgorandAuthenticationOptionsV2, AlgorandAuthenticationHandlerV2>(AlgorandAuthenticationHandlerV2.ID, AlgorandAuthenticationHandlerV2.ID, configureOptions);
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder, string authenticationScheme, Action<AlgorandAuthenticationOptionsV2> configureOptions)
            => builder.AddScheme<AlgorandAuthenticationOptionsV2, AlgorandAuthenticationHandlerV2>(authenticationScheme, authenticationScheme, configureOptions);
        public static AuthenticationBuilder AddAlgorand(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<AlgorandAuthenticationOptionsV2> configureOptions)
            => builder.AddScheme<AlgorandAuthenticationOptionsV2, AlgorandAuthenticationHandlerV2>(authenticationScheme, displayName, configureOptions);
    }
}
