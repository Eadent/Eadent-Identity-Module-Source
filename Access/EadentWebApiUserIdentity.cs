using Eadent.Common.WebApi.DataTransferObjects.Sessions.Users;
using Eadent.Common.WebApi.Definitions;
using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.DataAccess.EadentUserIdentity.Repositories;
using Eadent.Identity.Definitions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;

namespace Eadent.Identity.Access
{
    internal class EadentWebApiUserIdentity : IEadentWebApiUserIdentity
    {
        private ILogger<EadentWebApiUserIdentity> Logger { get; }

        private EadentIdentitySettings EadentIdentitySettings { get; }

        private IEadentUserIdentity EadentUserIdentity { get; }

        private IUserSessionsRepository UserSessionsRepository { get; }

        public EadentWebApiUserIdentity(ILogger<EadentWebApiUserIdentity> logger, IConfiguration configuration, IEadentUserIdentity eadentUserIdentity, IUserSessionsRepository userSessionsRepository)
        {
            Logger = logger;
            EadentIdentitySettings = configuration.GetSection(EadentIdentitySettings.SectionName).Get<EadentIdentitySettings>();
            EadentUserIdentity = eadentUserIdentity;
            UserSessionsRepository = userSessionsRepository;
        }

        public UserSessionSignInResponseDto SignInUser(UserSessionSignInRequestDto requestDto, string ipAddress)
        {
            var responseDto = new UserSessionSignInResponseDto();

            (SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc) = EadentUserIdentity.SignInUser(requestDto.EMailAddress, requestDto.PlainTextPassword, ipAddress, requestDto.GoogleReCaptchaScore);

            switch (signInStatusId)
            {
                case SignInStatus.Success:

                    responseDto.SessionToken = userSessionEntity.UserSessionGuid.ToString();
                    responseDto.PreviousSignInDateTimeUtc = previousUserSignInDateTimeUtc;
                    responseDto.SetSuccess();
                    break;

                // If a User tries to Sign In and Must Change their Password, force them to use a Web Site/Page to Change it otherwise they may never do so.
                case SignInStatus.SuccessUserMustChangePassword:

                    responseDto.SignInUrl = EadentIdentitySettings.UserIdentity.Account.SignInUrl;
                    responseDto.PreviousSignInDateTimeUtc = previousUserSignInDateTimeUtc;
                    responseDto.Set(DeveloperCode.SuccessUserMustChangePassword, "Success - User Must Change Password.");
                    break;

                case SignInStatus.UserLockedOut:

                    responseDto.SignInLockOutDateTimeUtc = userSessionEntity.User.SignInLockOutDateTimeUtc;
                    responseDto.SignInLockOutDurationSeconds = userSessionEntity.User.SignInLockOutDurationSeconds;
                    responseDto.Set(DeveloperCode.UserLockedOut, "User Is Locked Out.");
                    break;

                // To prevent any Hackers determining whether or not an E-Mail Address is Valid, we return generic Errors for most cases.
                case SignInStatus.Error:
                case SignInStatus.UserDisabled:
                case SignInStatus.InvalidEMailAddress:
                case SignInStatus.InvalidPassword:
                case SignInStatus.UserSoftDeleted:
                default:

                    responseDto.SetError();
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

                    responseDto.SetError();
                }
                else
                {
                    var userSessionEntity = UserSessionsRepository.GetFirstOrDefault(entity => entity.UserSessionGuid == userSessionGuid);

                    if (userSessionEntity == null)
                    {
                        Logger.LogError($"Invalid UserWebApiUserSessionToken: UserSessionGuid: {userSessionGuid}");

                        responseDto.SetError();
                    }
                    else
                    {
                        SessionStatus sessionStatusId = SessionStatus.Error;

                        (sessionStatusId, userSessionEntity) = EadentUserIdentity.CheckAndUpdateUserSession(userSessionEntity.UserSessionToken, ipAddress);

                        switch (sessionStatusId)
                        {
                            case SessionStatus.SignedIn:

                                responseDto.SetSuccess();
                                break;

                            case SessionStatus.TimedOutExpired:

                                responseDto.Set(DeveloperCode.SessionTimedOutExpired, "User Session Has Timed Out/Expired.");
                                break;

                            case SessionStatus.SignedOut:

                                responseDto.Set(DeveloperCode.SessionSignedOut, "User Session Is Signed Out.");
                                break;

                            case SessionStatus.InvalidSessionToken:

                                responseDto.SetUnauthorised();
                                break;

                            case SessionStatus.Error:
                            case SessionStatus.Inactive:
                            case SessionStatus.Disabled:
                            case SessionStatus.SoftDeleted:
                            default:

                                responseDto.SetError();
                                break;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                responseDto.SetError();
            }

            return responseDto;
        }

        public UserSessionSignOutResponseDto SignOutUser(string userWebApiSessionToken, string ipAddress)
        {
            var responseDto = new UserSessionSignOutResponseDto();

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

                    responseDto.SetError();
                }
                else
                {
                    var userSessionEntity = UserSessionsRepository.GetFirstOrDefault(entity => entity.UserSessionGuid == userSessionGuid);

                    if (userSessionEntity == null)
                    {
                        Logger.LogError($"Invalid UserWebApiUserSessionToken: UserSessionGuid: {userSessionGuid}");

                        responseDto.SetError();
                    }
                    else
                    {
                        SignOutStatus signOutStatusId = EadentUserIdentity.SignOutUser(userSessionEntity.UserSessionToken, ipAddress);

                        switch (signOutStatusId)
                        {
                            case SignOutStatus.Success:

                                responseDto.SetSuccess();
                                break;

                            case SignOutStatus.InvalidSessionToken:

                                responseDto.SetUnauthorised();
                                break;

                            case SignOutStatus.Error:
                            case SignOutStatus.InactiveSession:
                            case SignOutStatus.SessionAlreadySignedOut:
                            case SignOutStatus.SessionDisabled:
                            case SignOutStatus.SessionSoftDeleted:
                            default:

                                responseDto.SetError();
                                break;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                responseDto.SetError();
            }

            return responseDto;
        }
    }
}
