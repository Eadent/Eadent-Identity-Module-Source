using Eadent.Identity.Definitions;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("SignInStatuses")]
    public class SignInStatusEntity
    {
        public SignInStatusEntity()
        {
            UserSignIns = new HashSet<UserSessionEntity>();
        }

        [Key]
        public SignInStatus SignInStatusId { get; set; }

        public string Status { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }

        public virtual ICollection<UserSessionEntity> UserSignIns { get; set; }
    }
}
