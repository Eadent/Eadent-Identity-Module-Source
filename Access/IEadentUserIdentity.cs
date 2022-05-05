using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.Definitions;
using System;

namespace Eadent.Identity.Access
{
    public interface IEadentUserIdentity
    {
        (RegisterUserStatus registerUserStatusId, UserEntity userEntity) RegisterUser(int createdByApplicationId, string userGuidString, Role roleId, string displayName, string eMailAddress, string mobilePhoneNumber, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore);

        (SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc) SignInUser(SignInType signInTypeId, string eMailAddress, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore);

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
    }
}
