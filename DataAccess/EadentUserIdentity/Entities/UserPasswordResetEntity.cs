using Eadent.Identity.Definitions;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("UserPasswordResets")]
    public class UserPasswordResetEntity
    {
        [Key]
        public long UserPasswordResetId { get; set; }

        public PasswordResetStatus PasswordResetStatusId { get; set; }

        public string ResetToken { get; set; }

        public DateTime ResetTokenRequestedDateTimeUtc { get; set; }

        public int ResetTokenExpirationDurationSeconds { get; set; }

        public string EMailAddress { get; set; }

        public string UserIpAddress { get; set; }

        public long? UserId { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }

        public virtual UserEntity User { get; set; }
    }
}
