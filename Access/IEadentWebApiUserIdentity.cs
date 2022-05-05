using Eadent.Common.WebApi.DataTransferObjects.Sessions.Users;

namespace Eadent.Identity.Access
{
    public interface IEadentWebApiUserIdentity
    {
        UserSessionSignInResponseDto SignInUser(UserSessionSignInRequestDto requestDto, string userIpAddress);

        UserRegisterResponseDto RegisterUser(string userWebApiSessionToken, UserRegisterRequestDto requestDto, string userIpAddress);

        UserCheckAndUpdateSessionResponseDto CheckAndUpdateUserSession(string userWebApiSessionToken, UserCheckAndUpdateSessionRequestDto requestDto, string userIpAddress);

        UserSessionSignOutResponseDto SignOutUser(string userWebApiSessionToken, string userIpAddress);
    }
}
