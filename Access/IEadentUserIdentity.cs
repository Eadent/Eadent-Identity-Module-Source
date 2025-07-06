using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.Definitions;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Eadent.Identity.Access
{
    public interface IEadentUserIdentity
    {
        Task<(RegisterUserStatus registerUserStatusId, UserEntity userEntity)>
            RegisterUserAsync(int createdByApplicationId, string userGuidString, Role roleId, string displayName, string eMailAddress, string mobilePhoneNumber, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<(SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc)>
            SignInUserAsync(SignInType signInTypeId, string eMailAddress, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore, CancellationToken cancellationToken = default);

        // NOTE: As of 29-June-2025, this cannot be an asynchronous method because it is used in the constructor of the UserSession class.
        (SessionStatus sessionStatusId, UserSessionEntity userSessionEntity)
            CheckAndUpdateUserSession(string userSessionToken, string userIpAddress);

        Task<(ChangeUserEMailStatus changeUserEMailStatusId, UserSessionEntity userSessionEntity)>
            ChangeUserEMailAddressAsync(string userSessionToken, string plainTextPassword, string oldEMailAddress, string newEMailAddress, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<(ChangeUserPasswordStatus changeUserPasswordStatusId, UserSessionEntity userSessionEntity)>
            ChangeUserPasswordAsync(string userSessionToken, string oldPlainTextPassword, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<SignOutStatus>
            SignOutUserAsync(string userSessionToken, string userIpAddress, CancellationToken cancellationToken = default);

        Task<DeleteUserStatus>
            SoftDeleteUserAsync(string userSessionToken, Guid userGuid, string userIpAddress, CancellationToken cancellationToken = default);

        Task<DeleteUserStatus>
            SoftUnDeleteUserAsync(string userSessionToken, Guid userGuid, string userIpAddress, CancellationToken cancellationToken = default);

        Task<DeleteUserStatus>
            HardDeleteUserAsync(string userSessionToken, Guid userGuid, string userIpAddress, CancellationToken cancellationToken = default);

        Task<(UserPasswordResetStatus userPasswordResetStatusId, string displayName, string userPasswordResetCode)>
            BeginUserPasswordResetAsync(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<(UserPasswordResetStatus userPasswordResetStatusId, string displayName, string userPasswordResetCode)>
            RequestNewUserPasswordResetCodeAsync(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<UserPasswordResetStatus>
            TryUserPasswordResetCodeAsync(string eMailAddress, string userPasswordResetCode, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<UserPasswordResetStatus>
            CommitUserPasswordResetAsync(string eMailAddress, string userPasswordResetCode, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<UserPasswordResetStatus>
            RollBackUserPasswordResetAsync(string eMailAddress, string userPasswordResetCode, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        // The following are Administration methods that should not be used by the general public.
        Task<bool> AdminDoesUserExistAsync(string eMailAddress, CancellationToken cancellationToken = default);

        Task<UserEntity> AdminForceUserPasswordChangeAsync(string eMailAddress, Guid userGuid, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);
    }
}
