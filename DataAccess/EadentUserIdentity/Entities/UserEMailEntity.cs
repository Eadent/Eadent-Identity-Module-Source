using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("UserEMails")]
    public class UserEMailEntity
    {
        [Key]
        public long UserEMailId { get; set; }

        public long UserId { get; set; }

        public string EMailAddress { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual UserEntity User { get; set; }
    }
}
