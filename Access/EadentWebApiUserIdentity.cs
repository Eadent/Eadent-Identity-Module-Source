using Eadent.Common.WebApi.DataTransferObjects.Sessions.Users;
using Eadent.Common.WebApi.Definitions;
using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.DataAccess.EadentUserIdentity.Repositories;
using Eadent.Identity.Definitions;
using Eadent.Identity.Helpers;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

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

        public async Task<UserSessionSignInResponseDto> SignInUserAsync(UserSessionSignInRequestDto requestDto, string userIpAddress, CancellationToken cancellationToken)
        {
            var responseDto = new UserSessionSignInResponseDto();

            (SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc) = await EadentUserIdentity.SignInUserAsync(SignInType.WebApi, requestDto.EMailAddress, requestDto.PlainTextPassword, userIpAddress, googleReCaptchaScore: null, cancellationToken);

            switch (signInStatusId)
            {
                case SignInStatus.Success:

                    responseDto.SessionToken = userSessionEntity.UserSessionGuid.ToString();
                    responseDto.PreviousSignInDateTimeUtc = previousUserSignInDateTimeUtc;
                    responseDto.SetSuccess();
                    break;

                // If a User tries to Sign In and Must Change their Password, force them to use a Web Site/Page to Change it otherwise they may never do so.
                case SignInStatus.SuccessUserMustChangePassword:

                    responseDto.SignInUrl = EadentIdentitySettings.Instance.UserIdentity.Account.SignInUrl;
                    responseDto.PreviousSignInDateTimeUtc = previousUserSignInDateTimeUtc;
                    responseDto.Set((long)CommonDeveloperCode.SuccessUserMustChangePassword, "Success - User Must Change Password.");
                    break;

                case SignInStatus.UserLockedOut:

                    responseDto.SignInLockOutDateTimeUtc = userSessionEntity.User.SignInLockOutDateTimeUtc;
                    responseDto.SignInLockOutDurationSeconds = userSessionEntity.User.SignInLockOutDurationInSeconds;
                    responseDto.Set((long)CommonDeveloperCode.UserLockedOut, "User Is Locked Out.");
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

        public async Task<UserRegisterResponseDto> RegisterUserAsync(string userWebApiSessionToken, UserRegisterRequestDto requestDto, string userIpAddress, CancellationToken cancellationToken)
        {
            var responseDto = new UserRegisterResponseDto();

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
                    var userSessionEntity = UserSessionsRepository.GetFirstOrDefaultByUserSessionGuidIncludeUserAndRoles(userSessionGuid);

                    if (userSessionEntity == null)
                    {
                        Logger.LogError($"Invalid UserWebApiSessionToken: UserSessionGuid: {userSessionGuid}");

                        responseDto.SetError();
                    }
                    else if (!UserRoleHelper.IsPrivileged(userSessionEntity.User.UserRoles))
                    {
                        Logger.LogWarning($"Not Privilged So Cannot Register User.");

                        responseDto.Set((long)CommonDeveloperCode.Unauthorised, "Insufficient Privilege.");
                    }
                    else
                    {
                        (RegisterUserStatus registerUserStatusId, UserEntity userEntity) = await EadentUserIdentity.RegisterUserAsync(requestDto.CreatedByApplicationId,
                            requestDto.UserGuidString, (Role)requestDto.RoleId, requestDto.DisplayName, requestDto.EMailAddress, requestDto.MobilePhoneNumber,
                            requestDto.PlainTextPassword, userIpAddress, null, cancellationToken);

                        switch (registerUserStatusId)
                        {
                            case RegisterUserStatus.Success:

                                responseDto.SetSuccess();
                                responseDto.RegisterUserStatusId = (short)registerUserStatusId;
                                responseDto.UserId = userEntity.UserId;
                                responseDto.UserGuidString = userEntity.UserGuid.ToString();
                                break;

                            case RegisterUserStatus.UserAlreadyExists:

                                responseDto.Set((long)CommonDeveloperCode.UserAlreadyExists, "User Already Exists.");
                                break;

                            case RegisterUserStatus.Error:
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

        public UserCheckAndUpdateSessionResponseDto CheckAndUpdateUserSession(string userWebApiSessionToken, UserCheckAndUpdateSessionRequestDto requestDto, string userIpAddress)
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
                        Logger.LogError($"Invalid UserWebApiSessionToken: UserSessionGuid: {userSessionGuid}");

                        responseDto.SetError();
                    }
                    else
                    {
                        SessionStatus sessionStatusId = SessionStatus.Error;

                        (sessionStatusId, userSessionEntity) = EadentUserIdentity.CheckAndUpdateUserSession(userSessionEntity.UserSessionToken, userIpAddress);

                        switch (sessionStatusId)
                        {
                            case SessionStatus.SignedIn:

                                responseDto.SetSuccess();
                                break;

                            case SessionStatus.TimedOutExpired:

                                responseDto.Set((long)CommonDeveloperCode.SessionTimedOutExpired, "User Session Has Timed Out/Expired.");
                                break;

                            case SessionStatus.SignedOut:

                                responseDto.Set((long)CommonDeveloperCode.SessionSignedOut, "User Session Is Signed Out.");
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

        public async Task<UserSessionSignOutResponseDto> SignOutUserAsync(string userWebApiSessionToken, string userIpAddress, CancellationToken cancellationToken)
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
                    var userSessionEntity = await UserSessionsRepository.GetFirstOrDefaultAsync(entity => entity.UserSessionGuid == userSessionGuid, cancellationToken);

                    if (userSessionEntity == null)
                    {
                        Logger.LogError($"Invalid UserWebApiSessionToken: UserSessionGuid: {userSessionGuid}");

                        responseDto.SetError();
                    }
                    else
                    {
                        SignOutStatus signOutStatusId = await EadentUserIdentity.SignOutUserAsync(userSessionEntity.UserSessionToken, userIpAddress, cancellationToken);

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
