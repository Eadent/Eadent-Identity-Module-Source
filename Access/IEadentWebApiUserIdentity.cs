using Eadent.Common.WebApi.DataTransferObjects.Sessions.Users;
using System.Threading;
using System.Threading.Tasks;

namespace Eadent.Identity.Access
{
    public interface IEadentWebApiUserIdentity
    {
        Task<UserSessionSignInResponseDto> SignInUserAsync(UserSessionSignInRequestDto requestDto, string userIpAddress, CancellationToken cancellationToken = default);

        Task<UserRegisterResponseDto> RegisterUserAsync(string userWebApiSessionToken, UserRegisterRequestDto requestDto, string userIpAddress, CancellationToken cancellationToken = default);

        UserCheckAndUpdateSessionResponseDto CheckAndUpdateUserSession(string userWebApiSessionToken, UserCheckAndUpdateSessionRequestDto requestDto, string userIpAddress);

        Task<UserSessionSignOutResponseDto> SignOutUserAsync(string userWebApiSessionToken, string userIpAddress, CancellationToken cancellationToken = default);
    }
}
