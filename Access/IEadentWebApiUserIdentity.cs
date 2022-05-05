using Eadent.Common.WebApi.DataTransferObjects.Sessions.Users;
using Eadent.Common.WebApi.Definitions;

namespace Eadent.Identity.Access
{
    public interface IEadentWebApiUserIdentity
    {
        UserSessionSignInResponseDto SignInUser(UserSessionSignInRequestDto requestDto, string userIpAddress);

        UserCheckAndUpdateSessionResponseDto CheckAndUpdateUserSession(string userWebApiSessionToken, UserCheckAndUpdateSessionRequestDto requestDto, string userIpAddress);

        UserSessionSignOutResponseDto SignOutUser(string userWebApiSessionToken, string userIpAddress);
    }
}
