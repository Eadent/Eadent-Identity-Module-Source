using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.Definitions;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Eadent.Identity.Access
{
    public interface IEadentUserIdentity
    {
        (RegisterUserStatus registerUserStatusId, UserEntity userEntity) RegisterUser(int createdByApplicationId, string userGuidString, Role roleId, string displayName, string eMailAddress, string mobilePhoneNumber, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore);

        (SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc) SignInUser(SignInType signInTypeId, string eMailAddress, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore);

        // NOTE: As of 29-June-2025, this method cannot be an asynchronous method because it is used in the constructor of the UserSession class.
        (SessionStatus sessionStatusId, UserSessionEntity userSessionEntity) CheckAndUpdateUserSession(string userSessionToken, string userIpAddress);

        (ChangeUserEMailStatus changeUserEMailStatusId, UserSessionEntity userSessionEntity) ChangeUserEMailAddress(string userSessionToken, string plainTextPassword, string oldEMailAddress, string newEMailAddress, string userIpAddress, decimal googleReCaptchaScore);

        (ChangeUserPasswordStatus changeUserPasswordStatusId, UserSessionEntity userSessionEntity) ChangeUserPassword(string userSessionToken, string oldPlainTextPassword, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore);

        SignOutStatus SignOutUser(string userSessionToken, string userIpAddress);

        DeleteUserStatus SoftDeleteUser(string userSessionToken, Guid userGuid, string userIpAddress);

        DeleteUserStatus SoftUnDeleteUser(string userSessionToken, Guid userGuid, string userIpAddress);

        DeleteUserStatus HardDeleteUser(string userSessionToken, Guid userGuid, string userIpAddress);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, string resetToken, UserEntity userEntity) BeginUserPasswordReset(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) CheckAndUpdateUserPasswordReset(string resetToken, string userIpAddress);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) CommitUserPasswordReset(string resetToken, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) AbortUserPasswordReset(string resetToken, string userIpAddress);

        Task<(UserPasswordResetStatus userPasswordResetStatusId, string userPasswordResetCode)>
            BeginUserPasswordResetAsync(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<(UserPasswordResetStatus userPasswordResetStatusId, string userPasswordResetCode)>
            RequestNewUserPasswordResetCodeAsync(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<UserPasswordResetStatus>
            TryUserPasswordResetCodeAsync(string eMailAddress, string userPasswordResetCode, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<UserPasswordResetStatus>
            CommitUserPasswordResetAsync(string eMailAddress, string userPasswordResetCode, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        Task<UserPasswordResetStatus>
            RollBackUserPasswordResetAsync(string eMailAddress, string userPasswordResetCode, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default);

        // The following are Administration methods that should not be used by the general public.
        bool AdminDoesUserExist(string eMailAddress);

        UserEntity AdminForceUserPasswordChange(string eMailAddress, Guid userGuid, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore);
    }
}
