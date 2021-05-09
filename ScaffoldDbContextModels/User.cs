using System;
using System.Collections.Generic;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class User
    {
        public User()
        {
            PasswordResets = new HashSet<PasswordReset>();
            UserAudits = new HashSet<UserAudit>();
            UserEmails = new HashSet<UserEmail>();
            UserRoles = new HashSet<UserRole>();
            UserSessions = new HashSet<UserSession>();
        }

        public long UserId { get; set; }
        public Guid UserGuid { get; set; }
        public short UserStatusId { get; set; }
        public string DisplayName { get; set; }
        public short PasswordVersionId { get; set; }
        public Guid SaltGuid { get; set; }
        public string Password { get; set; }
        public DateTime PasswordDateTimeUtc { get; set; }
        public bool ChangePasswordNextSignIn { get; set; }
        public int SignInErrorCount { get; set; }
        public int SignInErrorLimit { get; set; }
        public DateTime? SignInLockOutDateTimeUtc { get; set; }
        public int SignInLockOutDurationMinutes { get; set; }
        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual PasswordVersion PasswordVersion { get; set; }
        public virtual UserStatus UserStatus { get; set; }
        public virtual ICollection<PasswordReset> PasswordResets { get; set; }
        public virtual ICollection<UserAudit> UserAudits { get; set; }
        public virtual ICollection<UserEmail> UserEmails { get; set; }
        public virtual ICollection<UserRole> UserRoles { get; set; }
        public virtual ICollection<UserSession> UserSessions { get; set; }
    }
}
