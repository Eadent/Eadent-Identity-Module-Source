using System;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.Definitions;

namespace Eadent.Identity.Access
{
    public interface IEadentUserIdentity
    {
        (RegisterUserStatus registerStatusId, UserEntity userEntity) RegisterUser(Role roleId, string eMailAddress, string displayName, string plainTextPassword, string ipAddress, decimal googleReCaptchaScore);

        (SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc) SignInUser(string eMailAddress, string plainTextPassword, string ipAddress, decimal? googleReCaptchaScore);

        (SessionStatus sessionStatusId, UserSessionEntity userSessionEntity) CheckAndUpdateUserSession(string userSessionToken, string ipAddress);

        (ChangeUserEMailStatus changeUserEMailStatusId, UserSessionEntity userSessionEntity) ChangeUserEMailAddress(string userSessionToken, string plainTextPassword, string oldEMailAddress, string newEMailAddress, string ipAddress, decimal googleReCaptchaScore);

        (ChangeUserPasswordStatus changeUserPasswordStatusId, UserSessionEntity userSessionEntity) ChangeUserPassword(string userSessionToken, string oldPlainTextPassword, string newPlainTextPassword, string ipAddress, decimal googleReCaptchaScore);

        SignOutStatus SignOutUser(string userSessionToken, string ipAddress);

        DeleteUserStatus SoftDeleteUser(string userSessionToken, Guid userGuid, string ipAddress);

        DeleteUserStatus SoftUnDeleteUser(string userSessionToken, Guid userGuid, string ipAddress);

        DeleteUserStatus HardDeleteUser(string userSessionToken, Guid userGuid, string ipAddress);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, string resetToken, UserEntity userEntity) BeginUserPasswordReset(string eMailAddress, string ipAddress, decimal googleReCaptchaScore);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) CheckAndUpdateUserPasswordReset(string resetToken, string ipAddress);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) CommitUserPasswordReset(string resetToken, string newPlainTextPassword, string ipAddress, decimal googleReCaptchaScore);

        (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) AbortUserPasswordReset(string resetToken, string ipAddress);
    }
}
