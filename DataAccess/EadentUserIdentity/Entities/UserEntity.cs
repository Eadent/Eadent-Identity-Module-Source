using Eadent.Identity.Definitions;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("Users")]
    public class UserEntity
    {
        public UserEntity()
        {
            UserRoles = new HashSet<UserRoleEntity>();
        }

        [Key]
        public long UserId { get; set; }

        public Guid UserGuid { get; set; }

        public UserStatus UserStatusId { get; set; }

        public int CreatedByApplicationId { get; set; }

        public SignInMultiFactorAuthenticationType SignInMultiFactorAuthenticationTypeId { get; set; }

        public string DisplayName { get; set; }

        public string EMailAddress { get; set; }

        public ConfirmationStatus EMailAddressConfirmationStatusId { get; set; }

        public string EMailAddressConfirmationCode { get; set; }

        public string MobilePhoneNumber { get; set; }

        public ConfirmationStatus MobilePhoneNumberConfirmationStatusId { get; set; }

        public string MobilePhoneNumberConfirmationCode { get; set; }

        public PasswordVersion PasswordVersionId { get; set; }

        public int PasswordHashIterationCount { get; set; }

        public int PasswordHashNumDerivedKeyBytes { get; set; }

        public Guid PasswordSaltGuid { get; set; }

        public string Password { get; set; }

        public DateTime PasswordLastUpdatedDateTimeUtc { get; set; }

        public bool ChangePasswordNextSignIn { get; set; }

        public int SignInErrorCount { get; set; }

        public int SignInErrorLimit { get; set; }

        public int SignInLockOutDurationSeconds { get; set; }

        public DateTime? SignInLockOutDateTimeUtc { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }

        public virtual PasswordVersionEntity PasswordVersion { get; set; }

        public virtual UserStatusEntity UserStatus { get; set; }

        public virtual ICollection<UserRoleEntity> UserRoles { get; set; }
    }
}
