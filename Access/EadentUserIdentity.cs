using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Eadent.Identity.DataAccess.EadentUserIdentity.Repositories;
using Eadent.Identity.Definitions;
using Eadent.Identity.Helpers;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PasswordVersion = Eadent.Identity.Definitions.PasswordVersion;
using Role = Eadent.Identity.Definitions.Role;
using SignInStatus = Eadent.Identity.Definitions.SignInStatus;
using UserStatus = Eadent.Identity.Definitions.UserStatus;

namespace Eadent.Identity.Access
{
    internal class EadentUserIdentity : IEadentUserIdentity
    {
        private ILogger<EadentUserIdentity> Logger { get; }

        private IEadentUserIdentityDatabase EadentUserIdentityDatabase { get; }

        private IUsersRepository UsersRepository { get; }

        private IUserRolesRepository UserRolesRepository { get; }

        private IUserAuditsRepository UserAuditsRepository { get; }

        private IUserSessionsRepository UserSessionsRepository { get; }

        private IUserPasswordResetsRepository UserPasswordResetsRepository { get; }

        public EadentUserIdentity(ILogger<EadentUserIdentity> logger, IConfiguration configuration,
            IEadentUserIdentityDatabase eadentUserIdentityDatabase,
            IUsersRepository usersRepository,
            IUserRolesRepository userRolesRepository, IUserAuditsRepository userAuditsRepository,
            IUserSessionsRepository userSessionsRepository, IUserPasswordResetsRepository userPasswordResetsRepository)
        {
            Logger = logger;
            EadentUserIdentityDatabase = eadentUserIdentityDatabase;
            UsersRepository = usersRepository;
            UserRolesRepository = userRolesRepository;
            UserAuditsRepository = userAuditsRepository;
            UserSessionsRepository = userSessionsRepository;
            UserPasswordResetsRepository = userPasswordResetsRepository;
        }

        private string HashSHA512(string source)
        {
            SHA512 sha512 = SHA512.Create();

            byte[] bytes = Encoding.Unicode.GetBytes(source);

            byte[] hash = sha512.ComputeHash(bytes);

            return Convert.ToBase64String(hash);
        }

        private string HashUserPasswordHMACSHA512(string plainTextPassword, int passwordHashIterationCount, int passwordHashNumDerivedKeyBytes, Guid saltGuid)
        {
            string hashedPassword = null;

            var settings = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher;

            byte[] salt = Encoding.Unicode.GetBytes($"{settings.PasswordSalt}-{saltGuid}");

            var derivedKey = KeyDerivation.Pbkdf2(plainTextPassword, salt, KeyDerivationPrf.HMACSHA512, passwordHashIterationCount, passwordHashNumDerivedKeyBytes);

            hashedPassword = Convert.ToBase64String(derivedKey);

            return hashedPassword;
        }

        private UserEntity CreateUser(int createdByApplicationId, string userGuidString, string displayName, string eMailAddress, string mobilePhoneNumber, string plainTextPassword, DateTime utcNow)
        {
            Guid? userGuid = null;

            if (!string.IsNullOrWhiteSpace(userGuidString))
            {
                if (Guid.TryParse(userGuidString, out var parsedUserGuid))
                    userGuid = parsedUserGuid;
            }

            if (userGuid == null)
                userGuid = Guid.NewGuid();

            var passwordSaltGuid = Guid.NewGuid();

            var passwordHashIterationCount = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.IterationCount;
            var passwordHashNumDerivedKeyBytes = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.NumDerivedKeyBytes;

            var userEntity = new UserEntity()
            {
                UserGuid = userGuid.GetValueOrDefault(),
                UserStatusId = UserStatus.Enabled,
                CreatedByApplicationId = createdByApplicationId,
                SignInMultiFactorAuthenticationTypeId = SignInMultiFactorAuthenticationType.None,
                DisplayName = displayName,
                EMailAddress = eMailAddress,
                EMailAddressConfirmationStatusId = ConfirmationStatus.NotConfirmed,
                EMailAddressConfirmationCode = null,
                MobilePhoneNumber = mobilePhoneNumber,
                MobilePhoneNumberConfirmationStatusId = ConfirmationStatus.NotConfirmed,
                MobilePhoneNumberConfirmationCode = null,
                PasswordVersionId = PasswordVersion.HMACSHA512,
                PasswordHashIterationCount = passwordHashIterationCount,
                PasswordHashNumDerivedKeyBytes = passwordHashNumDerivedKeyBytes,
                PasswordSaltGuid = passwordSaltGuid,
                Password = HashUserPasswordHMACSHA512(plainTextPassword, passwordHashIterationCount, passwordHashNumDerivedKeyBytes, passwordSaltGuid),
                PasswordLastUpdatedDateTimeUtc = utcNow,
                ChangePasswordNextSignIn = false,
                SignInErrorCount = 0,
                SignInErrorLimit = EadentIdentitySettings.Instance.UserIdentity.Account.SignInErrorLimit,
                SignInLockOutDurationInSeconds = EadentIdentitySettings.Instance.UserIdentity.Account.SignInLockOutDurationInSeconds,
                SignInLockOutDateTimeUtc = null,
                CreatedDateTimeUtc = utcNow,
                LastUpdatedDateTimeUtc = null
            };

            UsersRepository.Create(userEntity);
            UsersRepository.SaveChanges();

            return userEntity;
        }

        private UserRoleEntity CreateUserRole(UserEntity userEntity, Role roleId, DateTime utcNow)
        {
            var userRoleEntity = new UserRoleEntity()
            {
                UserId = userEntity.UserId,
                RoleId = roleId,
                CreatedDateTimeUtc = utcNow
            };

            UserRolesRepository.Create(userRoleEntity);

            return userRoleEntity;
        }

        private UserAuditEntity CreateUserAudit(long? userId, string description, string oldValue, string newValue, string userIpAddress, decimal? googleReCaptchaScore, DateTime utcNow)
        {
            var userAuditEntity = new UserAuditEntity()
            {
                UserId = userId,
                Activity = description,
                OldValue = oldValue,
                NewValue = newValue,
                UserIpAddress = userIpAddress,
                GoogleReCaptchaScore = googleReCaptchaScore,
                CreatedDateTimeUtc = utcNow
            };

            UserAuditsRepository.Create(userAuditEntity);

            return userAuditEntity;
        }

        private UserSessionEntity CreateUserSession(SignInType signInTypeId, UserEntity userEntity, string userSessionToken, UserSessionStatus userSessionStatusId, string eMailAddress, string userIpAddress, SignInStatus signInStatusId, DateTime utcNow)
        {
            var userSessionEntity = new UserSessionEntity()
            {
                UserSessionSignInTypeId = signInTypeId,
                UserSessionToken = userSessionToken,
                UserSessionGuid = Guid.NewGuid(),
                UserSessionStatusId = userSessionStatusId,
                UserSessionExpirationDurationInSeconds = EadentIdentitySettings.Instance.UserIdentity.Account.SessionExpirationDurationInSeconds,
                EMailAddress = eMailAddress,
                MobilePhoneNumber = userEntity?.MobilePhoneNumber,
                UserIpAddress = userIpAddress,
                SignInStatusId = signInStatusId,
                UserId = userEntity.UserId,
                CreatedDateTimeUtc = utcNow,
                LastUpdatedDateTimeUtc = utcNow
            };

            UserSessionsRepository.Create(userSessionEntity);

            return userSessionEntity;
        }

        private (UserSessionStatus userSessionStatusId, SignInStatus signInStatusId, DateTime? previousUserSignInDateTimeUtc) SignInEnabledUser(UserEntity userEntity, string hashedPassword, DateTime utcNow)
        {
            var userSessionStatusId = UserSessionStatus.Inactive;

            var signInStatusId = SignInStatus.Error;

            DateTime? previousUserSignInDateTimeUtc = null;

            try
            {
                if (hashedPassword == userEntity.Password)
                {
                    if (userEntity.ChangePasswordNextSignIn)
                    {
                        signInStatusId = SignInStatus.SuccessUserMustChangePassword;
                    }
                    else
                    {
                        signInStatusId = SignInStatus.Success;
                    }

                    userEntity.SignInErrorCount = 0;

                    userSessionStatusId = UserSessionStatus.SignedIn;

                    previousUserSignInDateTimeUtc = UserSessionsRepository.GetLastOrDefault(userEntity.UserId)?.CreatedDateTimeUtc;
                }
                else
                {
                    ++userEntity.SignInErrorCount;

                    if (userEntity.SignInErrorCount > userEntity.SignInErrorLimit)
                    {
                        signInStatusId = SignInStatus.UserLockedOut;

                        userEntity.SignInLockOutDateTimeUtc = utcNow;
                        userEntity.UserStatusId = UserStatus.SignInLockedOut;
                    }
                    else
                    {
                        signInStatusId = SignInStatus.InvalidPassword;
                    }
                }

                UsersRepository.Update(userEntity);
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");
            }

            return (userSessionStatusId, signInStatusId, previousUserSignInDateTimeUtc);
        }

        private (UserSessionStatus userSessionStatusId, SignInStatus signInStatusId, DateTime? previousUserSignInDateTimeUtc) SignInLockedOutUser(UserEntity userEntity, string hashedPassword, DateTime utcNow)
        {
            var userSessionStatusId = UserSessionStatus.Inactive;

            var signInStatusId = SignInStatus.Error;

            DateTime? previousUserSignInDateTimeUtc = null;

            // Just In Case of a Software or Database Administration Error, treat a null SignInLockOutDateTimeUtc as Lock Out Expired.
            if ((userEntity.SignInLockOutDateTimeUtc == null) ||
                (userEntity.SignInLockOutDateTimeUtc.Value.AddSeconds(userEntity.SignInLockOutDurationInSeconds) <= utcNow))
            {
                userEntity.SignInErrorCount = 0;
                userEntity.SignInLockOutDateTimeUtc = null;
                userEntity.UserStatusId = UserStatus.Enabled;

                (userSessionStatusId, signInStatusId, previousUserSignInDateTimeUtc) = SignInEnabledUser(userEntity, hashedPassword, utcNow);
            }
            else
            {
                signInStatusId = SignInStatus.UserLockedOut;
            }

            return (userSessionStatusId, signInStatusId, previousUserSignInDateTimeUtc);
        }

        private DeleteUserStatus PerformSoftDelete(UserEntity userEntity, bool selfSoftDelete, DateTime utcNow)
        {
            var deleteUserStatusId = DeleteUserStatus.Error;

            if (userEntity.UserStatusId == UserStatus.SoftDeleted)
            {
                deleteUserStatusId = DeleteUserStatus.AlreadySoftDeleted;
            }
            else
            {
                // 0. Update User Entity.
                userEntity.UserStatusId = UserStatus.SoftDeleted;
                UsersRepository.Update(userEntity);

                if (selfSoftDelete)
                {
                    // 1. Invalidate any User Sessions.
                    var parameters = new List<object>();

                    var userSessionStatusIdParameter = new SqlParameter("@UserSessionStatusId", SqlDbType.SmallInt) { Value = UserSessionStatus.SoftDeleted };
                    parameters.Add(userSessionStatusIdParameter);
                    var utcNowParameter = new SqlParameter("@UtcNow", SqlDbType.DateTime) { Value = utcNow };
                    parameters.Add(utcNowParameter);
                    var userIdParameter = new SqlParameter("@UserId", SqlDbType.BigInt) { Value = userEntity.UserId };
                    parameters.Add(userIdParameter);

                    var sql = $"UPDATE {EadentUserIdentityDatabase.DatabaseSchema}.UserSessions SET UserSessionStatusId = @UserSessionStatusId, LastAccessedDateTimeUtc = @UtcNow WHERE UserId = @UserId;";

                    var rowCount = EadentUserIdentityDatabase.ExecuteSqlRaw(sql, parameters);
                }

                deleteUserStatusId = DeleteUserStatus.SoftDeleted;
            }

            return deleteUserStatusId;
        }

        private DeleteUserStatus PerformSoftUnDelete(UserEntity userEntity)
        {
            var deleteUserStatusId = DeleteUserStatus.Error;

            if (userEntity.UserStatusId != UserStatus.SoftDeleted)
            {
                deleteUserStatusId = DeleteUserStatus.NotSoftDeleted;
            }
            else
            {
                userEntity.SignInErrorCount = 0;
                userEntity.SignInLockOutDateTimeUtc = null;
                userEntity.UserStatusId = UserStatus.Enabled;

                UsersRepository.Update(userEntity);

                deleteUserStatusId = DeleteUserStatus.SoftUnDeleted;
            }

            return deleteUserStatusId;
        }

        private DeleteUserStatus PerformHardDelete(UserEntity userEntity)
        {
            var deleteUserStatusId = DeleteUserStatus.Error;

            try
            {
                int rowCount = 0;

                var parameters = new List<object>();

                var userIdParameter = new SqlParameter("@UserId", SqlDbType.BigInt) { Value = userEntity.UserId };
                parameters.Add(userIdParameter);

                var sql = $"DELETE FROM {EadentUserIdentityDatabase.DatabaseSchema}.UserAudits WHERE UserId = @UserId;";
                rowCount = EadentUserIdentityDatabase.ExecuteSqlRaw(sql, parameters);

                sql = $"DELETE FROM {EadentUserIdentityDatabase.DatabaseSchema}.UserPasswordResets WHERE UserId = @UserId;";
                rowCount = EadentUserIdentityDatabase.ExecuteSqlRaw(sql, parameters);

                sql = $"DELETE FROM {EadentUserIdentityDatabase.DatabaseSchema}.UserRoles WHERE UserId = @UserId;";
                rowCount = EadentUserIdentityDatabase.ExecuteSqlRaw(sql, parameters);

                sql = $"DELETE FROM {EadentUserIdentityDatabase.DatabaseSchema}.UserSessions WHERE UserId = @UserId;";
                rowCount = EadentUserIdentityDatabase.ExecuteSqlRaw(sql, parameters);

                sql = $"DELETE FROM {EadentUserIdentityDatabase.DatabaseSchema}.Users WHERE UserId = @UserId;";
                rowCount = EadentUserIdentityDatabase.ExecuteSqlRaw(sql, parameters);

                deleteUserStatusId = DeleteUserStatus.HardDeleted;
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                deleteUserStatusId = DeleteUserStatus.Error;
            }

            return deleteUserStatusId;
        }

        public (RegisterUserStatus registerUserStatusId, UserEntity userEntity) RegisterUser(int createdByApplicationId, string userGuidString, Role roleId, string displayName, string eMailAddress, string mobilePhoneNumber, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore)
        {
            // TODO: Validate E-Mail Address.
            // TODO: Validate Mobile Phone Number.
            // TODO: Validate Plain Text Password.

            var registerUserStatusId = RegisterUserStatus.Error;

            UserEntity userEntity = null;

            try
            {
                var utcNow = DateTime.UtcNow;

                EadentUserIdentityDatabase.BeginTransaction();

                userEntity = UsersRepository.GetFirstOrDefaultByEMailAddressIncludeRoles(eMailAddress);

                if (userEntity != null)
                {
                    registerUserStatusId = RegisterUserStatus.UserAlreadyExists;
                }
                else
                {
                    userEntity = CreateUser(createdByApplicationId, userGuidString, displayName, eMailAddress, mobilePhoneNumber, plainTextPassword, utcNow);
                    CreateUserRole(userEntity, roleId, utcNow);

                    registerUserStatusId = RegisterUserStatus.Success;
                }

                Logger.LogInformation($"RegisterUserStatusId: {registerUserStatusId} : EMailAddress: {eMailAddress} : MobilePhoneNUmber: {mobilePhoneNumber} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity.UserId, $"User Register. RegisterUserStatusId: {registerUserStatusId}", null, $"Created By Application Id: {createdByApplicationId} : E-Mail Address: {eMailAddress} : Mobile Phone Number: {mobilePhoneNumber}", userIpAddress, googleReCaptchaScore, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
                EadentUserIdentityDatabase.CommitTransaction();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                EadentUserIdentityDatabase.RollbackTransaction();

                registerUserStatusId = RegisterUserStatus.Error;
            }

            return (registerUserStatusId, userEntity);
        }

        public (SignInStatus signInStatusId, UserSessionEntity userSessionEntity, DateTime? previousUserSignInDateTimeUtc) SignInUser(SignInType signInTypeId, string eMailAddress, string plainTextPassword, string userIpAddress, decimal? googleReCaptchaScore)
        {
            var signInStatusId = SignInStatus.Error;

            var userSessionStatusId = UserSessionStatus.Inactive;

            var utcNow = DateTime.UtcNow;

            UserSessionEntity userSessionEntity = null;

            DateTime? previousUserSignInDateTimeUtc = null;

            var passwordHashIterationCount = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.IterationCount;
            var passwordHashNumDerivedKeyBytes = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.NumDerivedKeyBytes;

            try
            {
                UserEntity userEntity = null;

                string userSessionToken = null;

                EadentUserIdentityDatabase.BeginTransaction();

                userEntity = UsersRepository.GetFirstOrDefaultByEMailAddressIncludeRoles(eMailAddress);

                string hashedPassword = null;

                if (userEntity == null)
                {
                    // Fake a Hashed Password.
                    hashedPassword = HashUserPasswordHMACSHA512(plainTextPassword, passwordHashIterationCount, passwordHashNumDerivedKeyBytes, Guid.NewGuid());

                    signInStatusId = SignInStatus.InvalidEMailAddress;
                }
                else
                {
                    switch (userEntity.PasswordVersionId)
                    {
                        case PasswordVersion.HMACSHA512:

                            hashedPassword = HashUserPasswordHMACSHA512(plainTextPassword, userEntity.PasswordHashIterationCount, userEntity.PasswordHashNumDerivedKeyBytes, userEntity.PasswordSaltGuid);
                            break;

                        default:

                            // Fake a Hashed Password.
                            hashedPassword = HashUserPasswordHMACSHA512(plainTextPassword, passwordHashIterationCount, passwordHashNumDerivedKeyBytes, Guid.NewGuid());
                            break;
                    }
                }

                userSessionToken = HashSHA512($"{EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.SiteSalt}-{Guid.NewGuid()}");

                if (userEntity != null)
                {
                    switch (userEntity.UserStatusId)
                    {
                        case UserStatus.Enabled:

                            (userSessionStatusId, signInStatusId, previousUserSignInDateTimeUtc) = SignInEnabledUser(userEntity, hashedPassword, utcNow);
                            break;

                        case UserStatus.Disabled:

                            signInStatusId = SignInStatus.UserDisabled;
                            break;

                        case UserStatus.SignInLockedOut:

                            (userSessionStatusId, signInStatusId, previousUserSignInDateTimeUtc) = SignInLockedOutUser(userEntity, hashedPassword, utcNow);
                            break;

                        case UserStatus.SoftDeleted:

                            signInStatusId = SignInStatus.UserSoftDeleted;
                            break;
                    }

                    userSessionEntity = CreateUserSession(signInTypeId, userEntity, userSessionToken, userSessionStatusId, eMailAddress, userIpAddress, signInStatusId, utcNow);
                }

                Logger.LogInformation($"SignInTypeId: {signInTypeId} : SignInStatusId: {signInStatusId} : EMailAddress: {eMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"User Sign In. SignInTypeId: {signInTypeId} : SignInStatusId: {signInStatusId}", null, $"E-Mail Address: {eMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
                EadentUserIdentityDatabase.CommitTransaction();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                EadentUserIdentityDatabase.RollbackTransaction();
            }

            return (signInStatusId, userSessionEntity, previousUserSignInDateTimeUtc);
        }

        // NOTE: As of 29-June-2025, this cannot be an asynchronous method because it is used in the constructor of the UserSession class.
        public (SessionStatus sessionStatusId, UserSessionEntity userSessionEntity) CheckAndUpdateUserSession(string userSessionToken, string userIpAddress)
        {
            var sessionStatusId = SessionStatus.Error;

            UserSessionEntity userSessionEntity = null;

            DateTime utcNow = DateTime.UtcNow;

            try
            {
                userSessionEntity = UserSessionsRepository.GetFirstOrDefaultIncludeUserAndRoles(userSessionToken);

                if (userSessionEntity == null)
                {
                    sessionStatusId = SessionStatus.InvalidSessionToken;
                }
                else
                {
                    switch (userSessionEntity.UserSessionStatusId)
                    {
                        case UserSessionStatus.Inactive:

                            sessionStatusId = SessionStatus.Inactive;
                            break;

                        case UserSessionStatus.SignedIn:

                            if (userSessionEntity.LastUpdatedDateTimeUtc.AddSeconds(userSessionEntity.UserSessionExpirationDurationInSeconds) <= utcNow)
                            {
                                userSessionEntity.UserSessionStatusId = UserSessionStatus.TimedOutExpired;

                                sessionStatusId = SessionStatus.TimedOutExpired;
                            }
                            else
                            {
                                sessionStatusId = SessionStatus.SignedIn;
                            }

                            userSessionEntity.LastUpdatedDateTimeUtc = utcNow;
                            UserSessionsRepository.Update(userSessionEntity);
                            break;

                        case UserSessionStatus.SignedOut:

                            sessionStatusId = SessionStatus.SignedOut;
                            break;

                        case UserSessionStatus.TimedOutExpired:

                            sessionStatusId = SessionStatus.TimedOutExpired;
                            break;

                        case UserSessionStatus.Disabled:

                            sessionStatusId = SessionStatus.Disabled;
                            break;

                        case UserSessionStatus.SoftDeleted:

                            sessionStatusId = SessionStatus.SoftDeleted;
                            break;
                    }
                }

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                sessionStatusId = SessionStatus.Error;
            }

            return (sessionStatusId, userSessionEntity);
        }

        public (ChangeUserEMailStatus changeUserEMailStatusId, UserSessionEntity userSessionEntity) ChangeUserEMailAddress(string userSessionToken, string plainTextPassword, string oldEMailAddress, string newEMailAddress, string userIpAddress, decimal googleReCaptchaScore)
        {
            // TODO: Validate New E-Mail Address.

            var changeUserEMailStatusId = ChangeUserEMailStatus.Error;

            UserSessionEntity userSessionEntity = null;

            UserEntity userEntity = null;

            DateTime utcNow = DateTime.UtcNow;

            var passwordHashIterationCount = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.IterationCount;
            var passwordHashNumDerivedKeyBytes = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.NumDerivedKeyBytes;

            try
            {
                userSessionEntity = UserSessionsRepository.GetFirstOrDefaultIncludeUserAndRoles(userSessionToken);

                if (userSessionEntity == null)
                {
                    changeUserEMailStatusId = ChangeUserEMailStatus.InvalidSessionToken;
                }
                else
                {
                    switch (userSessionEntity.UserSessionStatusId)
                    {
                        case UserSessionStatus.Inactive:

                            changeUserEMailStatusId = ChangeUserEMailStatus.SessionInactive;
                            break;

                        case UserSessionStatus.SignedIn:

                            string hashedPassword = null;

                            userEntity = userSessionEntity.User;

                            switch (userEntity.PasswordVersionId)
                            {
                                case PasswordVersion.HMACSHA512:

                                    hashedPassword = HashUserPasswordHMACSHA512(plainTextPassword, userEntity.PasswordHashIterationCount, userEntity.PasswordHashNumDerivedKeyBytes, userEntity.PasswordSaltGuid);
                                    break;

                                default:

                                    // Fake a Hashed Password.
                                    HashUserPasswordHMACSHA512(plainTextPassword, passwordHashIterationCount, passwordHashNumDerivedKeyBytes, Guid.NewGuid());
                                    break;
                            }

                            if (hashedPassword != userEntity.Password)
                            {
                                changeUserEMailStatusId = ChangeUserEMailStatus.InvalidPassword;
                            }
                            else
                            {
                                userEntity = UsersRepository.GetFirstOrDefaultByEMailAddressIncludeRoles(oldEMailAddress);

                                if (userEntity == null)
                                {
                                    changeUserEMailStatusId = ChangeUserEMailStatus.InvalidOldEMailAddress;
                                }
                                else
                                {
                                    if (userEntity.EMailAddress == newEMailAddress)
                                    {
                                        changeUserEMailStatusId = ChangeUserEMailStatus.Success;
                                    }
                                    else
                                    {
                                        userEntity.EMailAddress = newEMailAddress;
                                        userEntity.EMailAddressConfirmationStatusId = ConfirmationStatus.NotConfirmed;
                                        userEntity.EMailAddressConfirmationCode = null;

                                        UsersRepository.Update(userEntity);

                                        userSessionEntity.UserSessionStatusId = UserSessionStatus.SignedOut;
                                        userSessionEntity.LastUpdatedDateTimeUtc = utcNow;

                                        UserSessionsRepository.Update(userSessionEntity);

                                        changeUserEMailStatusId = ChangeUserEMailStatus.SuccessSignedOut;
                                    }
                                }
                            }
                            break;

                        case UserSessionStatus.SignedOut:

                            changeUserEMailStatusId = ChangeUserEMailStatus.SessionSignedOut;
                            break;

                        case UserSessionStatus.TimedOutExpired:

                            changeUserEMailStatusId = ChangeUserEMailStatus.SessionTimedOutExpired;
                            break;

                        case UserSessionStatus.Disabled:

                            changeUserEMailStatusId = ChangeUserEMailStatus.SessionDisabled;
                            break;

                        case UserSessionStatus.SoftDeleted:

                            changeUserEMailStatusId = ChangeUserEMailStatus.SessionSoftDeleted;
                            break;
                    }
                }

                Logger.LogInformation($"ChangeUserEMailStatusId: {changeUserEMailStatusId} : OldEMailAddress: {oldEMailAddress} : NewEMailAddress: {newEMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"User Change E-Mail Address. ChangeUserEMailStatusId: {changeUserEMailStatusId}", $"Old E-Mail Address: {oldEMailAddress}", $"New E-Mail Address: {newEMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                changeUserEMailStatusId = ChangeUserEMailStatus.Error;
            }

            return (changeUserEMailStatusId, userSessionEntity);
        }

        public (ChangeUserPasswordStatus changeUserPasswordStatusId, UserSessionEntity userSessionEntity) ChangeUserPassword(string userSessionToken, string oldPlainTextPassword, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore)
        {
            // TODO: Validate New Plain Text Password.

            var changeUserPasswordStatusId = ChangeUserPasswordStatus.Error;

            UserSessionEntity userSessionEntity = null;

            UserEntity userEntity = null;

            DateTime utcNow = DateTime.UtcNow;

            var passwordHashIterationCount = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.IterationCount;
            var passwordHashNumDerivedKeyBytes = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.NumDerivedKeyBytes;

            try
            {
                userSessionEntity = UserSessionsRepository.GetFirstOrDefaultIncludeUserAndRoles(userSessionToken);

                if (userSessionEntity == null)
                {
                    changeUserPasswordStatusId = ChangeUserPasswordStatus.InvalidSessionToken;
                }
                else
                {
                    switch (userSessionEntity.UserSessionStatusId)
                    {
                        case UserSessionStatus.Inactive:

                            changeUserPasswordStatusId = ChangeUserPasswordStatus.SessionInactive;
                            break;

                        case UserSessionStatus.SignedIn:

                            string hashedPassword = null;

                            userEntity = userSessionEntity.User;

                            switch (userEntity.PasswordVersionId)
                            {
                                case PasswordVersion.HMACSHA512:

                                    hashedPassword = HashUserPasswordHMACSHA512(oldPlainTextPassword, userEntity.PasswordHashIterationCount, userEntity.PasswordHashNumDerivedKeyBytes, userEntity.PasswordSaltGuid);
                                    break;

                                default:

                                    // Fake a Hashed Password.
                                    HashUserPasswordHMACSHA512(oldPlainTextPassword, passwordHashIterationCount, passwordHashNumDerivedKeyBytes, Guid.NewGuid());
                                    break;
                            }

                            if (hashedPassword != userEntity.Password)
                            {
                                changeUserPasswordStatusId = ChangeUserPasswordStatus.InvalidOldPassword;
                            }
                            else
                            {
                                string newHashedPassword = HashUserPasswordHMACSHA512(newPlainTextPassword, userEntity.PasswordHashIterationCount, userEntity.PasswordHashNumDerivedKeyBytes, userEntity.PasswordSaltGuid);

                                userEntity.PasswordVersionId = PasswordVersion.HMACSHA512;
                                userEntity.Password = newHashedPassword;
                                userEntity.PasswordLastUpdatedDateTimeUtc = utcNow;

                                UsersRepository.Update(userEntity);

                                userSessionEntity.UserSessionStatusId = UserSessionStatus.SignedOut;
                                userSessionEntity.LastUpdatedDateTimeUtc = utcNow;

                                UserSessionsRepository.Update(userSessionEntity);

                                changeUserPasswordStatusId = ChangeUserPasswordStatus.SuccessSignedOut;
                            }
                            break;

                        case UserSessionStatus.SignedOut:

                            changeUserPasswordStatusId = ChangeUserPasswordStatus.SessionSignedOut;
                            break;

                        case UserSessionStatus.TimedOutExpired:

                            changeUserPasswordStatusId = ChangeUserPasswordStatus.SessionTimedOutExpired;
                            break;

                        case UserSessionStatus.Disabled:

                            changeUserPasswordStatusId = ChangeUserPasswordStatus.SessionDisabled;
                            break;

                        case UserSessionStatus.SoftDeleted:

                            changeUserPasswordStatusId = ChangeUserPasswordStatus.SessionSoftDeleted;
                            break;
                    }
                }

                Logger.LogInformation($"ChangeUserPasswordStatusId: {changeUserPasswordStatusId} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"User Change Password. ChangeUserPasswordStatusId: {changeUserPasswordStatusId}", null, null, userIpAddress, googleReCaptchaScore, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                changeUserPasswordStatusId = ChangeUserPasswordStatus.Error;
            }

            return (changeUserPasswordStatusId, userSessionEntity);
        }

        public SignOutStatus SignOutUser(string userSessionToken, string userIpAddress)
        {
            var signOutStatusId = SignOutStatus.Error;

            var utcNow = DateTime.UtcNow;

            try
            {
                var userSessionEntity = UserSessionsRepository.GetFirstOrDefault(entity => entity.UserSessionToken == userSessionToken);

                if (userSessionEntity == null)
                {
                    signOutStatusId = SignOutStatus.InvalidSessionToken;
                }
                else
                {
                    switch (userSessionEntity.UserSessionStatusId)
                    {
                        case UserSessionStatus.Inactive:

                            signOutStatusId = SignOutStatus.InactiveSession;
                            break;

                        case UserSessionStatus.SignedIn:
                        case UserSessionStatus.TimedOutExpired:

                            userSessionEntity.UserSessionStatusId = UserSessionStatus.SignedOut;
                            userSessionEntity.LastUpdatedDateTimeUtc = utcNow;

                            UserSessionsRepository.Update(userSessionEntity);

                            signOutStatusId = SignOutStatus.Success;
                            break;

                        case UserSessionStatus.SignedOut:

                            signOutStatusId = SignOutStatus.SessionAlreadySignedOut;
                            break;

                        case UserSessionStatus.Disabled:

                            signOutStatusId = SignOutStatus.SessionDisabled;
                            break;

                        case UserSessionStatus.SoftDeleted:

                            signOutStatusId = SignOutStatus.SessionSoftDeleted;
                            break;
                    }
                }

                Logger.LogInformation($"SignOutStatusId: {signOutStatusId} : UserIpAddress: {userIpAddress}");

                CreateUserAudit(userSessionEntity?.UserId, $"User Sign Out. SignOutStatusId: {signOutStatusId}", null, null, userIpAddress, null, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                signOutStatusId = SignOutStatus.Error;
            }

            return signOutStatusId;
        }

        public DeleteUserStatus SoftDeleteUser(string userSessionToken, Guid userGuid, string userIpAddress)
        {
            var deleteUserStatusId = DeleteUserStatus.Error;

            DateTime utcNow = DateTime.UtcNow;

            try
            {
                EadentUserIdentityDatabase.BeginTransaction();

                long? initiatingUserId = null;
                long? targetUserId = null;

                UserSessionEntity userSessionEntity = UserSessionsRepository.GetFirstOrDefaultIncludeUserAndRoles(userSessionToken);

                if (userSessionEntity == null)
                {
                    deleteUserStatusId = DeleteUserStatus.InvalidSessionToken;
                }
                else
                {
                    initiatingUserId = userSessionEntity.UserId;

                    if (userSessionEntity.UserSessionStatusId != UserSessionStatus.SignedIn)
                    {
                        switch (userSessionEntity.UserSessionStatusId)
                        {
                            case UserSessionStatus.Inactive:

                                deleteUserStatusId = DeleteUserStatus.SessionInactive;
                                break;

                            case UserSessionStatus.SignedOut:

                                deleteUserStatusId = DeleteUserStatus.SessionSignedOut;
                                break;

                            case UserSessionStatus.TimedOutExpired:

                                deleteUserStatusId = DeleteUserStatus.SessionTimedOutExpired;
                                break;

                            case UserSessionStatus.Disabled:

                                deleteUserStatusId = DeleteUserStatus.SessionDisabled;
                                break;

                            case UserSessionStatus.SoftDeleted:

                                deleteUserStatusId = DeleteUserStatus.SessionSoftDeleted;
                                break;
                        }
                    }
                    else if (userSessionEntity.User.UserGuid == userGuid)
                    {
                        // We are Attempting to Soft Delete ourselves.
                        targetUserId = userSessionEntity.UserId;
                        deleteUserStatusId = PerformSoftDelete(userSessionEntity.User, true, utcNow);
                    }
                    else
                    {
                        if (!UserRoleHelper.IsPrivileged(userSessionEntity.User.UserRoles))
                        {
                            deleteUserStatusId = DeleteUserStatus.NotAuthorisedToSoftDeleteAnotherUser;
                        }
                        else
                        {
                            // We are Attempting to Soft Delete another User.
                            var targetUserEntity = UsersRepository.GetFirstOrDefault(entity => entity.UserGuid == userGuid);

                            if (targetUserEntity == null)
                            {
                                deleteUserStatusId = DeleteUserStatus.UserNotFound;
                            }
                            else
                            {
                                targetUserId = targetUserEntity.UserId;
                                deleteUserStatusId = PerformSoftDelete(targetUserEntity, false, utcNow);
                            }
                        }
                    }
                }

                Logger.LogInformation($"DeleteUserStatusId: {deleteUserStatusId} : InitiatingUserId: {initiatingUserId} - TargetUserId: {targetUserId} : UserIpAddress: {userIpAddress}");

                CreateUserAudit(initiatingUserId, $"User Soft Delete. DeleteUserStatusId: {deleteUserStatusId}", null, $"Initiating User Id: {initiatingUserId} - Target User Id: {targetUserId}", userIpAddress, null, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
                EadentUserIdentityDatabase.CommitTransaction();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                EadentUserIdentityDatabase.RollbackTransaction();

                deleteUserStatusId = DeleteUserStatus.Error;
            }

            return deleteUserStatusId;
        }

        public DeleteUserStatus SoftUnDeleteUser(string userSessionToken, Guid userGuid, string userIpAddress)
        {
            var deleteUserStatusId = DeleteUserStatus.Error;

            DateTime utcNow = DateTime.UtcNow;

            try
            {
                EadentUserIdentityDatabase.BeginTransaction();

                long? initiatingUserId = null;
                long? targetUserId = null;

                UserSessionEntity userSessionEntity = UserSessionsRepository.GetFirstOrDefaultIncludeUserAndRoles(userSessionToken);

                if (userSessionEntity == null)
                {
                    deleteUserStatusId = DeleteUserStatus.InvalidSessionToken;
                }
                else
                {
                    initiatingUserId = userSessionEntity.UserId;

                    if (userSessionEntity.UserSessionStatusId != UserSessionStatus.SignedIn)
                    {
                        switch (userSessionEntity.UserSessionStatusId)
                        {
                            case UserSessionStatus.Inactive:

                                deleteUserStatusId = DeleteUserStatus.SessionInactive;
                                break;

                            case UserSessionStatus.SignedOut:

                                deleteUserStatusId = DeleteUserStatus.SessionSignedOut;
                                break;

                            case UserSessionStatus.TimedOutExpired:

                                deleteUserStatusId = DeleteUserStatus.SessionTimedOutExpired;
                                break;

                            case UserSessionStatus.Disabled:

                                deleteUserStatusId = DeleteUserStatus.SessionDisabled;
                                break;

                            case UserSessionStatus.SoftDeleted:

                                deleteUserStatusId = DeleteUserStatus.SessionSoftDeleted;
                                break;
                        }
                    }
                    else if (userSessionEntity.User.UserGuid == userGuid)
                    {
                        // We may not Soft Un-Delete ourself.
                        targetUserId = userSessionEntity.UserId;
                        deleteUserStatusId = DeleteUserStatus.MayNotSoftUnDeleteSelf;
                    }
                    else if (!UserRoleHelper.IsPrivileged(userSessionEntity.User.UserRoles))
                    {
                        deleteUserStatusId = DeleteUserStatus.NotAuthorisedToSoftUnDeleteAnotherUser;
                    }
                    else
                    {
                        // We are Attempting to Soft Un-Delete another User.
                        var targetUserEntity = UsersRepository.GetFirstOrDefault(entity => entity.UserGuid == userGuid);

                        if (targetUserEntity == null)
                        {
                            deleteUserStatusId = DeleteUserStatus.UserNotFound;
                        }
                        else
                        {
                            targetUserId = targetUserEntity.UserId;
                            deleteUserStatusId = PerformSoftUnDelete(targetUserEntity);
                        }
                    }
                }

                Logger.LogInformation($"DeleteUserStatusId: {deleteUserStatusId} : InitiatingUserId: {initiatingUserId} - TargetUserId: {targetUserId} : UserIpAddress: {userIpAddress}");

                CreateUserAudit(initiatingUserId, $"User Soft Un-Delete. DeleteUserStatusId: {deleteUserStatusId}", null, $"Initiating User Id: {initiatingUserId} - Target User Id: {targetUserId}", userIpAddress, null, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
                EadentUserIdentityDatabase.CommitTransaction();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception occurred.");

                EadentUserIdentityDatabase.RollbackTransaction();

                deleteUserStatusId = DeleteUserStatus.Error;
            }

            return deleteUserStatusId;
        }

        public DeleteUserStatus HardDeleteUser(string userSessionToken, Guid userGuid, string userIpAddress)
        {
            var deleteUserStatusId = DeleteUserStatus.Error;

            DateTime utcNow = DateTime.UtcNow;

            try
            {
                EadentUserIdentityDatabase.BeginTransaction();

                long? initiatingUserId = null;
                long? targetUserId = null;

                UserSessionEntity userSessionEntity = UserSessionsRepository.GetFirstOrDefaultIncludeUserAndRoles(userSessionToken);

                if (userSessionEntity == null)
                {
                    deleteUserStatusId = DeleteUserStatus.InvalidSessionToken;
                }
                else
                {
                    initiatingUserId = userSessionEntity.UserId;

                    if (userSessionEntity.UserSessionStatusId != UserSessionStatus.SignedIn)
                    {
                        switch (userSessionEntity.UserSessionStatusId)
                        {
                            case UserSessionStatus.Inactive:

                                deleteUserStatusId = DeleteUserStatus.SessionInactive;
                                break;

                            case UserSessionStatus.SignedOut:

                                deleteUserStatusId = DeleteUserStatus.SessionSignedOut;
                                break;

                            case UserSessionStatus.TimedOutExpired:

                                deleteUserStatusId = DeleteUserStatus.SessionTimedOutExpired;
                                break;

                            case UserSessionStatus.Disabled:

                                deleteUserStatusId = DeleteUserStatus.SessionDisabled;
                                break;

                            case UserSessionStatus.SoftDeleted:

                                deleteUserStatusId = DeleteUserStatus.SessionSoftDeleted;
                                break;
                        }
                    }
                    else if (userSessionEntity.User.UserGuid == userGuid)
                    {
                        // We may not hard Delete ourself.
                        targetUserId = userSessionEntity.UserId;
                        deleteUserStatusId = DeleteUserStatus.MayNotHardDeleteSelf;
                    }
                    else if (!UserRoleHelper.IsPrivileged(userSessionEntity.User.UserRoles))
                    {
                        deleteUserStatusId = DeleteUserStatus.NotAuthorisedToHardDeleteAnotherUser;
                    }
                    else
                    {
                        // We are Attempting to Hard Delete another User.
                        var targetUserEntity = UsersRepository.GetFirstOrDefault(entity => entity.UserGuid == userGuid);

                        if (targetUserEntity == null)
                        {
                            deleteUserStatusId = DeleteUserStatus.UserNotFound;
                        }
                        else
                        {
                            targetUserId = targetUserEntity.UserId;
                            deleteUserStatusId = PerformHardDelete(targetUserEntity);
                        }
                    }
                }

                Logger.LogInformation($"DeleteUserStatusId: {deleteUserStatusId} : InitiatingUserId: {initiatingUserId} - TargetUserId: {targetUserId} : UserIpAddress: {userIpAddress}");

                CreateUserAudit(initiatingUserId, $"User Hard Delete. DeleteUserStatusId: {deleteUserStatusId}", null, $"Initiating User Id: {initiatingUserId} - Target User Id: {targetUserId}", userIpAddress, null, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
                EadentUserIdentityDatabase.CommitTransaction();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                EadentUserIdentityDatabase.RollbackTransaction();

                deleteUserStatusId = DeleteUserStatus.Error;
            }

            return deleteUserStatusId;
        }

#if false
        public (UserPasswordResetRequestStatus passwordResetRequestStatusId, string resetToken, UserEntity userEntity) BeginUserPasswordReset(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore)
        {
            var passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;

            string resetToken = null;

            UserEntity userEntity = null;

            var utcNow = DateTime.UtcNow;

            try
            {
                resetToken = HashSHA512($"{EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.SiteSalt}-{Guid.NewGuid()}");

                userEntity = UsersRepository.GetFirstOrDefaultByEMailAddressIncludeRoles(eMailAddress);

                if (userEntity == null)
                {
                    passwordResetRequestStatusId = UserPasswordResetRequestStatus.InvalidEMailAddress;
                }
                else
                {
                    switch (userEntity.UserStatusId)
                    {
                        case UserStatus.Enabled:
                        case UserStatus.SignInLockedOut:

                            CreatePasswordReset(resetToken, eMailAddress, userIpAddress, userEntity, utcNow);

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Success;
                            break;

                        case UserStatus.Disabled:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.UserDisabled;
                            break;

                        case UserStatus.SoftDeleted:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.UserSoftDeleted;
                            break;
                    }
                }

                Logger.LogInformation($"PasswordResetRequestStatusId: {passwordResetRequestStatusId} : EMailAddress: {eMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"Password Reset Begin Request. PasswordResetRequestStatusId: {passwordResetRequestStatusId}", null, $"E-Mail Address: {eMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;
            }

            return (passwordResetRequestStatusId, resetToken, userEntity);
        }

        public (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) CheckAndUpdateUserPasswordReset(string resetToken, string userIpAddress)
        {
            var passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;

            UserPasswordResetEntity userPasswordResetEntity = null;

            DateTime utcNow = DateTime.UtcNow;

            try
            {
                userPasswordResetEntity = UserPasswordResetsRepository.GetFirstOrDefault(entity => entity.ResetToken == resetToken);

                if (userPasswordResetEntity == null)
                {
                    passwordResetRequestStatusId = UserPasswordResetRequestStatus.InvalidResetToken;
                }
                else
                {
                    switch (userPasswordResetEntity.PasswordResetStatusId)
                    {
                        case PasswordResetStatus.Open:

                            if (userPasswordResetEntity.ResetTokenRequestedDateTimeUtc.AddSeconds(userPasswordResetEntity.ResetTokenExpirationDurationSeconds) <= utcNow)
                            {
                                userPasswordResetEntity.PasswordResetStatusId = PasswordResetStatus.TimedOutExpired;
                                UserPasswordResetsRepository.Update(userPasswordResetEntity);

                                passwordResetRequestStatusId = UserPasswordResetRequestStatus.TimedOutExpired;
                            }
                            else
                            {
                                passwordResetRequestStatusId = UserPasswordResetRequestStatus.Success;
                            }
                            break;

                        case PasswordResetStatus.Aborted:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Aborted;
                            break;

                        case PasswordResetStatus.TimedOutExpired:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.TimedOutExpired;
                            break;

                        case PasswordResetStatus.Closed:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Closed;
                            break;
                    }
                }

                Logger.LogInformation($"PasswordResetRequestStatusId: {passwordResetRequestStatusId} : UserIpAddress: {userIpAddress}");

                CreateUserAudit(userPasswordResetEntity?.UserId, $"Password Reset Check And Update Request. PasswordResetRequestStatusId: {passwordResetRequestStatusId}", null, null, userIpAddress, null, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;
            }

            return (passwordResetRequestStatusId, userPasswordResetEntity);
        }

        public (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) CommitUserPasswordReset(string resetToken, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore)
        {
            // TODO: Validate New Plain Text Password.

            var passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;

            UserPasswordResetEntity userPasswordResetEntity = null;

            DateTime utcNow = DateTime.UtcNow;

            try
            {
                userPasswordResetEntity = UserPasswordResetsRepository.GetFirstOrDefault(entity => entity.ResetToken == resetToken);

                if (userPasswordResetEntity == null)
                {
                    passwordResetRequestStatusId = UserPasswordResetRequestStatus.InvalidResetToken;
                }
                else
                {
                    switch (userPasswordResetEntity.PasswordResetStatusId)
                    {
                        case PasswordResetStatus.Open:

                            if (userPasswordResetEntity.ResetTokenRequestedDateTimeUtc.AddSeconds(userPasswordResetEntity.ResetTokenExpirationDurationSeconds) <= utcNow)
                            {
                                userPasswordResetEntity.PasswordResetStatusId = PasswordResetStatus.TimedOutExpired;
                                UserPasswordResetsRepository.Update(userPasswordResetEntity);

                                passwordResetRequestStatusId = UserPasswordResetRequestStatus.TimedOutExpired;
                            }
                            else
                            {
                                var userEntity = UsersRepository.Get(userPasswordResetEntity.UserId.GetValueOrDefault(-1));

                                if (userEntity == null)
                                {
                                    passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;
                                }
                                else
                                {
                                    userPasswordResetEntity.PasswordResetStatusId = PasswordResetStatus.Closed;

                                    UserPasswordResetsRepository.Update(userPasswordResetEntity);

                                    string newHashedPassword = HashUserPasswordHMACSHA512(newPlainTextPassword, userEntity.PasswordHashIterationCount, userEntity.PasswordHashNumDerivedKeyBytes, userEntity.PasswordSaltGuid);

                                    userEntity.PasswordVersionId = PasswordVersion.HMACSHA512;
                                    userEntity.Password = newHashedPassword;
                                    userEntity.PasswordLastUpdatedDateTimeUtc = utcNow;

                                    UsersRepository.Update(userEntity);

                                    passwordResetRequestStatusId = UserPasswordResetRequestStatus.Success;
                                }
                            }
                            break;

                        case PasswordResetStatus.Aborted:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Aborted;
                            break;

                        case PasswordResetStatus.TimedOutExpired:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.TimedOutExpired;
                            break;

                        case PasswordResetStatus.Closed:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Closed;
                            break;
                    }
                }

                Logger.LogInformation($"PasswordResetRequestStatusId: {passwordResetRequestStatusId} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userPasswordResetEntity?.UserId, $"Password Reset Commit Request. PasswordResetRequestStatusId: {passwordResetRequestStatusId}", null, null, userIpAddress, googleReCaptchaScore, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;
            }

            return (passwordResetRequestStatusId, userPasswordResetEntity);
        }

        public (UserPasswordResetRequestStatus passwordResetRequestStatusId, UserPasswordResetEntity passwordResetEntity) AbortUserPasswordReset(string resetToken, string userIpAddress)
        {
            var passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;

            UserPasswordResetEntity userPasswordResetEntity = null;

            DateTime utcNow = DateTime.UtcNow;

            try
            {
                userPasswordResetEntity = UserPasswordResetsRepository.GetFirstOrDefault(entity => entity.ResetToken == resetToken);

                if (userPasswordResetEntity == null)
                {
                    passwordResetRequestStatusId = UserPasswordResetRequestStatus.InvalidResetToken;
                }
                else
                {
                    switch (userPasswordResetEntity.PasswordResetStatusId)
                    {
                        case PasswordResetStatus.Open:

                            userPasswordResetEntity.PasswordResetStatusId = PasswordResetStatus.Aborted;
                            UserPasswordResetsRepository.Update(userPasswordResetEntity);

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Aborted;
                            break;

                        case PasswordResetStatus.Aborted:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Aborted;
                            break;

                        case PasswordResetStatus.TimedOutExpired:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.TimedOutExpired;
                            break;

                        case PasswordResetStatus.Closed:

                            passwordResetRequestStatusId = UserPasswordResetRequestStatus.Closed;
                            break;
                    }
                }

                Logger.LogInformation($"PasswordResetRequestStatusId: {passwordResetRequestStatusId} : UserIpAddress: {userIpAddress}");

                CreateUserAudit(userPasswordResetEntity?.UserId, $"Password Reset Abort Request. PasswordResetRequestStatusId: {passwordResetRequestStatusId}", null, null, userIpAddress, null, utcNow);

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                passwordResetRequestStatusId = UserPasswordResetRequestStatus.Error;
            }

            return (passwordResetRequestStatusId, userPasswordResetEntity);
        }
#endif

        public async Task<(UserPasswordResetStatus userPasswordResetStatusId, string displayName, string userPasswordResetCode)>
            BeginUserPasswordResetAsync(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default)
        {
            UserPasswordResetStatus userPasswordResetStatusId = UserPasswordResetStatus.Error;

            string displayName = eMailAddress;

            string userPasswordResetCode = null;

            try
            {
                DateTime utcNow = DateTime.UtcNow;

                UserEntity userEntity = null;

                UserPasswordResetEntity userPasswordResetEntity = await UserPasswordResetsRepository.GetLastOrDefaultAsync(entity => entity.EMailAddress == eMailAddress, entity => entity.UserPasswordResetId, cancellationToken);

                if (userPasswordResetEntity == null)
                {
                    userEntity = await UsersRepository.GetFirstOrDefaultByEMailAddressIncludeRolesAsync(eMailAddress, cancellationToken);

                    if (userEntity == null)
                    {
                        userPasswordResetStatusId = UserPasswordResetStatus.InvalidEMailAddress;
                    }
                    else
                    {
                        userPasswordResetStatusId = UserPasswordResetStatus.NewRequest;

                        userPasswordResetCode = GenerateUserPasswordResetCode();
                    }
                }
                else
                {
                    userEntity = await UsersRepository.GetAsync(userPasswordResetEntity.UserId, cancellationToken);

                    if (userPasswordResetEntity.ResetFirstRequestedDateTimeUtc.AddSeconds(userPasswordResetEntity.ResetWindowDurationInSeconds) <= utcNow)
                    {
                        // The PasswordReset has Expired so New PasswordReset Request.
                        userPasswordResetStatusId = UserPasswordResetStatus.NewRequest;

                        userPasswordResetCode = GenerateUserPasswordResetCode();

                        await UserPasswordResetsRepository.DeleteAsync(userPasswordResetEntity, cancellationToken);
                    }
                    else
                    {
                        userPasswordResetStatusId = UserPasswordResetStatus.OutstandingRequest;

                        userPasswordResetCode = userPasswordResetEntity.PasswordResetCode;
                    }
                }

                if (userEntity != null)
                {
                    displayName = userEntity.DisplayName;

                    switch (userEntity.UserStatusId)
                    {
                        case UserStatus.Enabled:
                        case UserStatus.SignInLockedOut:

                            if (userPasswordResetStatusId == UserPasswordResetStatus.NewRequest)
                            {
                                userPasswordResetEntity = await CreatePasswordResetAsync(userPasswordResetCode, eMailAddress, userIpAddress, userEntity, utcNow, cancellationToken);
                            }
                            break;

                        case UserStatus.Disabled:

                            userPasswordResetStatusId = UserPasswordResetStatus.UserDisabled;
                            break;

                        case UserStatus.SoftDeleted:

                            userPasswordResetStatusId = UserPasswordResetStatus.UserSoftDeleted;
                            break;
                    }
                }

                Logger.LogInformation($"UserPasswordResetStatusId: {userPasswordResetStatusId} : EMailAddress: {eMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"Password Reset Begin. UserPasswordResetStatusId: {userPasswordResetStatusId}", null, $"E-Mail Address: {eMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                await EadentUserIdentityDatabase.SaveChangesAsync(cancellationToken);
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                userPasswordResetStatusId = UserPasswordResetStatus.Error;
            }

            return (userPasswordResetStatusId, displayName, userPasswordResetCode);
        }

        public async Task<(UserPasswordResetStatus userPasswordResetStatusId, string displayName, string userPasswordResetCode)>
            RequestNewUserPasswordResetCodeAsync(string eMailAddress, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default)
        {
            UserPasswordResetStatus userPasswordResetStatusId = UserPasswordResetStatus.Error;

            string displayName = null;

            string userPasswordResetCode = null;

            try
            {
                DateTime utcNow = DateTime.UtcNow;

                UserEntity userEntity = null;

                UserPasswordResetEntity userPasswordResetEntity = await UserPasswordResetsRepository.GetLastOrDefaultAsync(entity => entity.EMailAddress == eMailAddress, entity => entity.UserPasswordResetId, cancellationToken);

                if (userPasswordResetEntity == null)
                {
                    userPasswordResetStatusId = UserPasswordResetStatus.InvalidEMailAddress;
                }
                else
                {
                    if (userPasswordResetEntity.ResetFirstRequestedDateTimeUtc.AddSeconds(userPasswordResetEntity.ResetWindowDurationInSeconds) <= utcNow)
                    {
                        // The PasswordReset has Timed Out and Expired.
                        userPasswordResetStatusId = UserPasswordResetStatus.TimedOutExpired;

                        await UserPasswordResetsRepository.DeleteAsync(userPasswordResetEntity, cancellationToken);
                    }
                    else if (userPasswordResetEntity.RequestCodeCount >= userPasswordResetEntity.RequestCodeLimit)
                    {
                        // The PasswordReset has reached the Request Count Limit.
                        userPasswordResetStatusId = UserPasswordResetStatus.LimitsReached;
                    }
                    else
                    {
                        userEntity = await UsersRepository.GetAsync(userPasswordResetEntity.UserId, cancellationToken);

                        if (userEntity == null)
                        {
                            userPasswordResetStatusId = UserPasswordResetStatus.Error;
                        }
                        else
                        {
                            displayName = userEntity.DisplayName;

                            switch (userEntity.UserStatusId)
                            {
                                case UserStatus.Enabled:
                                case UserStatus.SignInLockedOut:

                                    userPasswordResetStatusId = UserPasswordResetStatus.NewRequest;

                                    userPasswordResetCode = GenerateUserPasswordResetCode();

                                    userPasswordResetEntity.PasswordResetCode = userPasswordResetCode;
                                    ++userPasswordResetEntity.RequestCodeCount;
                                    userPasswordResetEntity.LastUpdatedDateTimeUtc = utcNow;

                                    await UserPasswordResetsRepository.UpdateAsync(userPasswordResetEntity, cancellationToken);
                                    break;

                                case UserStatus.Disabled:

                                    userPasswordResetStatusId = UserPasswordResetStatus.UserDisabled;
                                    break;

                                case UserStatus.SoftDeleted:

                                    userPasswordResetStatusId = UserPasswordResetStatus.UserSoftDeleted;
                                    break;
                            }
                        }
                    }
                }

                Logger.LogInformation($"UserPasswordResetStatusId: {userPasswordResetStatusId} : EMailAddress: {eMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"Password Reset Request New Reset Code. UserPasswordResetStatusId: {userPasswordResetStatusId}", null, $"E-Mail Address: {eMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                await EadentUserIdentityDatabase.SaveChangesAsync(cancellationToken);
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                userPasswordResetStatusId = UserPasswordResetStatus.Error;
            }

            return (userPasswordResetStatusId, displayName, userPasswordResetCode);
        }

        public async Task<UserPasswordResetStatus>
            TryUserPasswordResetCodeAsync(string eMailAddress, string userPasswordResetCode, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default)
        {
            UserPasswordResetStatus userPasswordResetStatusId = UserPasswordResetStatus.Error;

            try
            {
                DateTime utcNow = DateTime.UtcNow;

                UserEntity userEntity = null;

                UserPasswordResetEntity userPasswordResetEntity = await UserPasswordResetsRepository.GetLastOrDefaultAsync(entity => entity.EMailAddress == eMailAddress, entity => entity.UserPasswordResetId, cancellationToken);

                if (userPasswordResetEntity == null)
                {
                    userPasswordResetStatusId = UserPasswordResetStatus.InvalidEMailAddress;
                }
                else
                {
                    if (userPasswordResetEntity.ResetFirstRequestedDateTimeUtc.AddSeconds(userPasswordResetEntity.ResetWindowDurationInSeconds) <= utcNow)
                    {
                        // The PasswordReset has Timed Out and Expired.
                        userPasswordResetStatusId = UserPasswordResetStatus.TimedOutExpired;

                        await UserPasswordResetsRepository.DeleteAsync(userPasswordResetEntity, cancellationToken);
                    }
                    else if (userPasswordResetEntity.TryCodeCount >= userPasswordResetEntity.TryCodeLimit)
                    {
                        // The PasswordReset has reached the Try Count Limit.
                        userPasswordResetStatusId = UserPasswordResetStatus.LimitsReached;
                    }
                    else
                    {
                        userEntity = await UsersRepository.GetAsync(userPasswordResetEntity.UserId, cancellationToken);

                        if (userEntity == null)
                        {
                            userPasswordResetStatusId = UserPasswordResetStatus.Error;
                        }
                        else
                        {
                            switch (userEntity.UserStatusId)
                            {
                                case UserStatus.Enabled:
                                case UserStatus.SignInLockedOut:

                                    if (userPasswordResetCode == userPasswordResetEntity.PasswordResetCode)
                                    {
                                        userPasswordResetStatusId = UserPasswordResetStatus.ValidResetCode;
                                    }
                                    else
                                    {
                                        userPasswordResetStatusId = UserPasswordResetStatus.InvalidResetCode;
                                    }

                                    ++userPasswordResetEntity.TryCodeCount;
                                    userPasswordResetEntity.LastUpdatedDateTimeUtc = utcNow;

                                    await UserPasswordResetsRepository.UpdateAsync(userPasswordResetEntity, cancellationToken);

                                    if (userPasswordResetEntity.TryCodeCount >= userPasswordResetEntity.TryCodeLimit)
                                    {
                                        // The PasswordReset has reached the Try Count Limit.
                                        userPasswordResetStatusId = UserPasswordResetStatus.LimitsReached;
                                    }
                                    break;

                                case UserStatus.Disabled:

                                    userPasswordResetStatusId = UserPasswordResetStatus.UserDisabled;
                                    break;

                                case UserStatus.SoftDeleted:

                                    userPasswordResetStatusId = UserPasswordResetStatus.UserSoftDeleted;
                                    break;
                            }
                        }
                    }
                }

                Logger.LogInformation($"UserPasswordResetStatusId: {userPasswordResetStatusId} : EMailAddress: {eMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"Password Reset Try Reset Code. UserPasswordResetStatusId: {userPasswordResetStatusId}", null, $"E-Mail Address: {eMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                await EadentUserIdentityDatabase.SaveChangesAsync(cancellationToken);
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                userPasswordResetStatusId = UserPasswordResetStatus.Error;
            }

            return userPasswordResetStatusId;
        }

        public async Task<UserPasswordResetStatus>
            CommitUserPasswordResetAsync(string eMailAddress, string userPasswordResetCode, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default)
        {
            // TODO: Validate New Plain Text Password.

            UserPasswordResetStatus userPasswordResetStatusId = UserPasswordResetStatus.Error;

            try
            {
                DateTime utcNow = DateTime.UtcNow;

                UserEntity userEntity = null;

                UserPasswordResetEntity userPasswordResetEntity = await UserPasswordResetsRepository.GetLastOrDefaultAsync(entity => entity.EMailAddress == eMailAddress, entity => entity.UserPasswordResetId, cancellationToken);

                if (userPasswordResetEntity == null)
                {
                    userPasswordResetStatusId = UserPasswordResetStatus.InvalidEMailAddress;
                }
                else
                {
                    if (userPasswordResetEntity.ResetFirstRequestedDateTimeUtc.AddSeconds(userPasswordResetEntity.ResetWindowDurationInSeconds) <= utcNow)
                    {
                        // The PasswordReset has Timed Out and Expired.
                        userPasswordResetStatusId = UserPasswordResetStatus.TimedOutExpired;

                        await UserPasswordResetsRepository.DeleteAsync(userPasswordResetEntity, cancellationToken);
                    }
                    else
                    {
                        userEntity = await UsersRepository.GetAsync(userPasswordResetEntity.UserId, cancellationToken);

                        if (userEntity == null)
                        {
                            userPasswordResetStatusId = UserPasswordResetStatus.Error;
                        }
                        else
                        {
                            switch (userEntity.UserStatusId)
                            {
                                case UserStatus.Enabled:
                                case UserStatus.SignInLockedOut:

                                    if (userPasswordResetCode == userPasswordResetEntity.PasswordResetCode)
                                    {
                                        userPasswordResetStatusId = UserPasswordResetStatus.ValidResetCode;

                                        string newHashedPassword = HashUserPasswordHMACSHA512(newPlainTextPassword, userEntity.PasswordHashIterationCount, userEntity.PasswordHashNumDerivedKeyBytes, userEntity.PasswordSaltGuid);

                                        userEntity.SignInErrorCount = 0;
                                        userEntity.SignInLockOutDateTimeUtc = null;
                                        userEntity.UserStatusId = UserStatus.Enabled;
                                        userEntity.PasswordVersionId = PasswordVersion.HMACSHA512;
                                        userEntity.Password = newHashedPassword;
                                        userEntity.PasswordLastUpdatedDateTimeUtc = utcNow;

                                        await UsersRepository.UpdateAsync(userEntity, cancellationToken);
                                        await UserPasswordResetsRepository.DeleteAsync(userPasswordResetEntity, cancellationToken);
                                    }
                                    else
                                    {
                                        userPasswordResetStatusId = UserPasswordResetStatus.InvalidResetCode;
                                        userPasswordResetEntity.LastUpdatedDateTimeUtc = utcNow;

                                        await UserPasswordResetsRepository.UpdateAsync(userPasswordResetEntity, cancellationToken);
                                    }

                                    break;

                                case UserStatus.Disabled:

                                    userPasswordResetStatusId = UserPasswordResetStatus.UserDisabled;
                                    break;

                                case UserStatus.SoftDeleted:

                                    userPasswordResetStatusId = UserPasswordResetStatus.UserSoftDeleted;
                                    break;
                            }
                        }
                    }
                }

                Logger.LogInformation($"UserPasswordResetStatusId: {userPasswordResetStatusId} : EMailAddress: {eMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"Password Reset Commit. UserPasswordResetStatusId: {userPasswordResetStatusId}", null, $"E-Mail Address: {eMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                await EadentUserIdentityDatabase.SaveChangesAsync(cancellationToken);
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                userPasswordResetStatusId = UserPasswordResetStatus.Error;
            }

            return userPasswordResetStatusId;
        }

        // TODO: REVIEW: What was the logic behind this method? We should NOT delete a Password Reset Code just if we Cancel? Or should we?
        //               If we get as far as Entering and Confirming a New Password, then we should delete the Password Reset Code?
        //               Is there any risk to Deleting a Password Reset Code if we Cancel the Password Reset at the Enter New Password stage?
        //               Basically, the Password Reset Code was notionally Successful and got us to the Enter New Password stage so it has been "used"?
        //               What if a User moves away from the Page without entering a New Password? The Password Reset Code is still valid?
        //               So does Roll Back make sense?
        //               It may only be helpful to stop the Database Table from filling up with expired Password Reset Codes?
        //               But then, we should probably just delete all Password Reset Codes that are older than a certain age?
        //               Incidentally, do we need an "PasswordResetCodeUsed" Status?
        //               And update the Table after the Enter Password Reset Code but before the Enter New Password stage?
        public async Task<UserPasswordResetStatus>
            RollBackUserPasswordResetAsync(string eMailAddress, string userPasswordResetCode, string userIpAddress, decimal googleReCaptchaScore, CancellationToken cancellationToken = default)
        {
            UserPasswordResetStatus userPasswordResetStatusId = UserPasswordResetStatus.Error;

            try
            {
                DateTime utcNow = DateTime.UtcNow;

                UserEntity userEntity = null;

                UserPasswordResetEntity userPasswordResetEntity = await UserPasswordResetsRepository.GetLastOrDefaultAsync(entity => entity.EMailAddress == eMailAddress, entity => entity.UserPasswordResetId, cancellationToken);

                if (userPasswordResetEntity == null)
                {
                    userPasswordResetStatusId = UserPasswordResetStatus.InvalidEMailAddress;
                }
                else
                {
                    if (userPasswordResetEntity.ResetFirstRequestedDateTimeUtc.AddSeconds(userPasswordResetEntity.ResetWindowDurationInSeconds) <= utcNow)
                    {
                        // The PasswordReset has Timed Out and Expired.
                        userPasswordResetStatusId = UserPasswordResetStatus.TimedOutExpired;

                        await UserPasswordResetsRepository.DeleteAsync(userPasswordResetEntity, cancellationToken);
                    }
                    else
                    {
                        userEntity = await UsersRepository.GetAsync(userPasswordResetEntity.UserId, cancellationToken);

                        if (userEntity == null)
                        {
                            userPasswordResetStatusId = UserPasswordResetStatus.Error;
                        }
                        else
                        {
                            if (userPasswordResetCode == userPasswordResetEntity.PasswordResetCode)
                            {
                                userPasswordResetStatusId = UserPasswordResetStatus.ValidResetCode;

                                await UserPasswordResetsRepository.DeleteAsync(userPasswordResetEntity, cancellationToken);
                            }
                            else
                            {
                                userPasswordResetStatusId = UserPasswordResetStatus.InvalidResetCode;
                            }
                        }
                    }
                }

                Logger.LogInformation($"UserPasswordResetStatusId: {userPasswordResetStatusId} : EMailAddress: {eMailAddress} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                CreateUserAudit(userEntity?.UserId, $"Password Reset Roll Back. UserPasswordResetStatusId: {userPasswordResetStatusId}", null, $"E-Mail Address: {eMailAddress}", userIpAddress, googleReCaptchaScore, utcNow);

                await EadentUserIdentityDatabase.SaveChangesAsync(cancellationToken);
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                userPasswordResetStatusId = UserPasswordResetStatus.Error;
            }

            return userPasswordResetStatusId;
        }

        // The following are Administration methods that should not be used by the general public.

        public bool AdminDoesUserExist(string eMailAddress)
        {
            bool userExists = false;

            try
            {
                UserEntity userEntity = UsersRepository.GetFirstOrDefaultByEMailAddressIncludeRoles(eMailAddress);

                if (userEntity != null)
                {
                    userExists = true;
                }
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");
            }

            return userExists;
        }

        public UserEntity AdminForceUserPasswordChange(string eMailAddress, Guid userGuid, string newPlainTextPassword, string userIpAddress, decimal googleReCaptchaScore)
        {
            // TODO: Validate New Plain Text Password.

            UserEntity userEntity = null;

            DateTime utcNow = DateTime.UtcNow;

            var passwordHashIterationCount = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.IterationCount;
            var passwordHashNumDerivedKeyBytes = EadentIdentitySettings.Instance.UserIdentity.Security.Hasher.NumDerivedKeyBytes;

            try
            {
                userEntity = UsersRepository.GetFirstOrDefaultByEMailAddressAndUserGuidIncludeRoles(eMailAddress, userGuid);

                if (userEntity != null)
                {
                    string newHashedPassword = HashUserPasswordHMACSHA512(newPlainTextPassword, userEntity.PasswordHashIterationCount, userEntity.PasswordHashNumDerivedKeyBytes, userEntity.PasswordSaltGuid);

                    userEntity.PasswordVersionId = PasswordVersion.HMACSHA512;
                    userEntity.Password = newHashedPassword;
                    userEntity.PasswordLastUpdatedDateTimeUtc = utcNow;

                    UsersRepository.Update(userEntity);

                    Logger.LogInformation($"AdminForceUserPasswordChange: Success : EMailAddress: {eMailAddress} : UserGuid: {userGuid} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                    CreateUserAudit(userEntity?.UserId, $"Force User Password Change. Success : EMailAddress: {eMailAddress} : UserGuid: {userGuid}", null, null, userIpAddress, googleReCaptchaScore, utcNow);
                }
                else
                {
                    Logger.LogInformation($"AdminForceUserPasswordChange: Error : EMailAddress: {eMailAddress} : UserGuid: {userGuid} : UserIpAddress: {userIpAddress} : GoogleReCaptchaScore: {googleReCaptchaScore}");

                    CreateUserAudit(userEntity?.UserId, $"Force User Password Change. Error : EMailAddress: {eMailAddress} : UserGuid: {userGuid}", null, null, userIpAddress, googleReCaptchaScore, utcNow);
                }

                EadentUserIdentityDatabase.SaveChanges();
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "An Exception has occurred.");

                userEntity = null;
            }

            return userEntity;
        }

        // Courtesy of Copilot.
        private string GenerateUserPasswordResetCode()
        {
            // Generate a random integer between 0 and 999999 (inclusive).
            var randomNumber = RandomNumberGenerator.GetInt32(0, 1_000_000);

            // Format as a 6-digit, zero-padded string.
            return randomNumber.ToString("D6");
        }

        private async Task<UserPasswordResetEntity> CreatePasswordResetAsync(string userPasswordResetCode, string eMailAddress, string userIpAddress, UserEntity userEntity, DateTime utcNow, CancellationToken cancellationToken)
        {
            var passwordResetSettings = EadentIdentitySettings.Instance.UserIdentity.Account.PasswordReset;

            var userPasswordResetEntity = new UserPasswordResetEntity()
            {
                UserId = userEntity.UserId,
                EMailAddress = eMailAddress,
                PasswordResetCode = userPasswordResetCode,
                ResetFirstRequestedDateTimeUtc = utcNow,
                ResetWindowDurationInSeconds = passwordResetSettings.ResetWindowDurationInMinutes * 60,
                RequestCodeCount = 0,
                RequestCodeLimit = passwordResetSettings.RequestCodeLimit,
                TryCodeCount = 0,
                TryCodeLimit = passwordResetSettings.TryCodeLimit,
                UserIpAddress = userIpAddress,
                CreatedDateTimeUtc = utcNow,
                LastUpdatedDateTimeUtc = null
            };

            await UserPasswordResetsRepository.CreateAsync(userPasswordResetEntity, cancellationToken);

            return userPasswordResetEntity;
        }
    }
}
