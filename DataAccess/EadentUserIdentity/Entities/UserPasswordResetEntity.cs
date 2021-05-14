using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Eadent.Identity.Definitions;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("UserPasswordResets")]
    public class UserPasswordResetEntity
    {
        [Key]
        public long UserPasswordResetId { get; set; }

        public PasswordResetStatus PasswordResetStatusId { get; set; }

        public string ResetToken { get; set; }

        public DateTime RequestedDateTimeUtc { get; set; }

        public int ExpirationDurationSeconds { get; set; }

        public string EMailAddress { get; set; }

        public string IpAddress { get; set; }

        public long? UserId { get; set; }

        public virtual UserEntity User { get; set; }
    }
}
