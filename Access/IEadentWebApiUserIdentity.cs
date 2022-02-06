using Eadent.Common.WebApi.DataTransferObjects.Sessions.Users;
using Eadent.Common.WebApi.Definitions;

namespace Eadent.Identity.Access
{
    public interface IEadentWebApiUserIdentity
    {
        UserSessionSignInResponseDto SignInUser(UserSessionSignInRequestDto requestDto, string ipAddress);

        UserCheckAndUpdateSessionResponseDto CheckAndUpdateUserSession(string userWebApiSessionToken, UserCheckAndUpdateSessionRequestDto requestDto, string ipAddress);

        UserSessionSignOutResponseDto SignOutUser(string userWebApiSessionToken, string ipAddress);
    }
}
