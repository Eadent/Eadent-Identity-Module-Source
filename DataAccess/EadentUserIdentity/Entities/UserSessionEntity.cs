using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Eadent.Identity.Definitions;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("UserSessions")]
    public class UserSessionEntity
    {
        [Key]
        public long UserSessionId { get; set; }

        public string UserSessionToken { get; set; }

        public Guid UserSessionGuid { get; set; }

        public UserSessionStatus UserSessionStatusId { get; set; }

        public int UserSessionExpirationDurationSeconds { get; set; }

        public string EMailAddress { get; set; }

        public string IpAddress { get; set; }

        public SignInStatus SignInStatusId { get; set; }

        public long? UserId { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime LastAccessedDateTimeUtc { get; set; }

        public virtual SignInStatusEntity SignInStatus { get; set; }

        public virtual UserEntity User { get; set; }
    }
}
