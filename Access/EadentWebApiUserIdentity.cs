using System;
using Eadent.Common.WebApi.DataTransferObjects.Sessions.Users;
using Eadent.Common.WebApi.Definitions;
using Eadent.Common.WebApi.Helpers;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.DataAccess.EadentUserIdentity.Repositories;
using Eadent.Identity.Definitions;
using Microsoft.Extensions.Logging;

namespace Eadent.Identity.Access
{
    internal class EadentWebApiUserIdentity : IEadentWebApiUserIdentity
    {
        private ILogger<EadentWebApiUserIdentity> Logger { get; }

        private IEadentUserIdentity EadentUserIdentity { get; }

        private IUserSessionsRepository UserSessionsRepository { get; }

        public EadentWebApiUserIdentity(ILogger<EadentWebApiUserIdentity> logger, IEadentUserIdentity eadentUserIdentity, IUserSessionsRepository userSessionsRepository)
        {
            Logger = logger;
            EadentUserIdentity = eadentUserIdentity;
            UserSessionsRepository = userSessionsRepository;
        }

        public UserSessionSignInResponseDto SignInUser(UserSessionSignInRequestDto requestDto, string ipAddress, decimal? googleReCaptchaScore)
        {
            var responseDto = new UserSessionSignInResponseDto();

            (SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc) = EadentUserIdentity.SignInUser(requestDto.EMailAddress, requestDto.PlainTextPassword, ipAddress, googleReCaptchaScore);

            switch (signInStatusId)
            {
                case SignInStatus.Success:

                    responseDto.DeveloperCode = DeveloperCode.Success;
                    responseDto.DeveloperMessage = "Success.";
                    responseDto.SessionToken = userSessionEntity.UserSessionGuid.ToString();
                    responseDto.PreviousSignInDateTimeUtc = previousUserSignInDateTimeUtc;
                    break;

                // If a User tries to Sign In and Must Change their Password, force them to use a Web Site/Page to Change it otherwise they may never do so.
                case SignInStatus.SuccessUserMustChangePassword:

                    responseDto.DeveloperCode = DeveloperCode.SuccessUserMustChangePasssword;
                    responseDto.DeveloperMessage = "Success - User Must Change Password.";
                    responseDto.PreviousSignInDateTimeUtc = previousUserSignInDateTimeUtc;
                    break;

                case SignInStatus.UserLockedOut:

                    responseDto.DeveloperCode = DeveloperCode.UserLockedOut;
                    responseDto.DeveloperMessage = "User Locked Out.";
                    responseDto.SignInLockOutDateTimeUtc = userSessionEntity.User.SignInLockOutDateTimeUtc;
                    responseDto.SignInLockOutDurationSeconds = userSessionEntity.User.SignInLockOutDurationSeconds;
                    break;

                // To prevent any Hackers determining whether or not an E-Mail Address is Valid, we return generic Errors for most cases.
                case SignInStatus.Error:
                case SignInStatus.UserDisabled:
                case SignInStatus.InvalidEMailAddress:
                case SignInStatus.InvalidPassword:
                case SignInStatus.UserSoftDeleted:
                default:

                    responseDto.DeveloperCode = DeveloperCode.Error;
                    responseDto.DeveloperMessage = "Error.";
                    break;
            }

            return responseDto;
        }

        public UserCheckAndUpdateSessionResponseDto CheckAndUpdateUserSession(string userWebApiSessionToken, UserCheckAndUpdateSessionRequestDto requestDto, string ipAddress)
        {
            var responseDto = new UserCheckAndUpdateSessionResponseDto();

            try
            {
                Guid userSessionGuid = Guid.Empty;

                if (userWebApiSessionToken != null)
                {
                    Guid.TryParse(userWebApiSessionToken, out userSessionGuid);
                }

                if (userSessionGuid == Guid.Empty)
                {
                    Logger.LogError($"Invalid UserWebApiSessionToken: {userWebApiSessionToken}");

                    responseDto.DeveloperCode = DeveloperCode.Error;
                    responseDto.DeveloperMessage = "Error.";
                }
                else
                {
                    var userSessionEntity = UserSessionsRepository.GetFirstOrDefault(entity => entity.UserSessionGuid == userSessionGuid);

                    if (userSessionEntity == null)
                    {
                        Logger.LogError($"Invalid UserWebApiUserSessionToken: UserSessionGuid: {userSessionGuid}");

                        responseDto.DeveloperCode = DeveloperCode.Error;
                        responseDto.DeveloperMessage = "Error.";
                    }
                    else
                    {
                        SessionStatus sessionStatusId = SessionStatus.Error;

                        (sessionStatusId, userSessionEntity) = EadentUserIdentity.CheckAndUpdateUserSession(userSessionEntity.UserSessionToken, ipAddress);
#if false
                        switch (sessionStatusId)
                        {
                                Error = 0,
                                Inactive = 1,
                                InvalidSessionToken = 2,
                                SignedIn = 3,
                                SignedOut = 4,
                                TimedOutExpired = 5,
                                Disabled = 6,
                                SoftDeleted = 100
                        }
#endif
                    }
                }
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                responseDto.DeveloperCode = DeveloperCode.Error;
            }

            return responseDto;
        }

        public UserSessionSignOutResponseDto SignOutUser(string userWebApiSessionToken, string ipAddress)
        {
            throw new System.NotImplementedException();
        }
    }
}
