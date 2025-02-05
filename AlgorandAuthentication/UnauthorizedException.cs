using System;

namespace AlgorandAuthentication
{
    public class UnauthorizedException : Exception
    {
        public UnauthorizedException(string message) : base(message)
        {

        }
    }
}

namespace AlgorandAuthenticationV2
{
    public class UnauthorizedException : AlgorandAuthentication.UnauthorizedException
    {
        public UnauthorizedException(string message) : base(message)
        {

        }
    }
}
