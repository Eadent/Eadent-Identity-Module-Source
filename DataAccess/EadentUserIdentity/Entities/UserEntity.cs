using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Eadent.Identity.Definitions;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("Users")]
    public class UserEntity
    {
        public UserEntity()
        {
            UserEmails = new HashSet<UserEMailEntity>();
            UserRoles = new HashSet<UserRoleEntity>();
        }

        [Key]
        public long UserId { get; set; }

        public Guid UserGuid { get; set; }

        public UserStatus UserStatusId { get; set; }

        public string DisplayName { get; set; }

        public PasswordVersion PasswordVersionId { get; set; }

        public Guid SaltGuid { get; set; }

        public string Password { get; set; }

        public DateTime PasswordDateTimeUtc { get; set; }

        public bool ChangePasswordNextSignIn { get; set; }

        public int SignInErrorCount { get; set; }

        public int SignInErrorLimit { get; set; }

        public int SignInLockOutDurationSeconds { get; set; }

        public DateTime? SignInLockOutDateTimeUtc { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual PasswordVersionEntity PasswordVersion { get; set; }

        public virtual UserStatusEntity UserStatus { get; set; }

        public virtual ICollection<UserEMailEntity> UserEmails { get; set; }

        public virtual ICollection<UserRoleEntity> UserRoles { get; set; }
    }
}
