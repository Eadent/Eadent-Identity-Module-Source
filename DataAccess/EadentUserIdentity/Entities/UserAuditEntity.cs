using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("UserAudits")]
    public class UserAuditEntity
    {
        [Key]
        public long UserAuditId { get; set; }

        public long? UserId { get; set; }

        public string Description { get; set; }

        public string OldValue { get; set; }

        public string NewValue { get; set; }

        public string IpAddress { get; set; }

        [Column(TypeName=("decimal(5, 2)"))]
        public decimal? GoogleReCaptchaScore { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual UserEntity User { get; set; }
    }
}
