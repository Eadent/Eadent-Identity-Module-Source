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

        public long UserId { get; set; }

        public string EMailAddress { get; set; }

        public string PasswordResetCode { get; set; }

        public DateTime ResetFirstRequestedDateTimeUtc { get; set; }

        public int ResetWindowDurationInSeconds { get; set; }

        public byte RequestCodeCount { get; set; }

        public byte RequestCodeLimit { get; set; }

        public byte TryCodeCount { get; set; }

        public byte TryCodeLimit { get; set; }

        public string UserIpAddress { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }
    }
}
