using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Eadent.Identity.Definitions;

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

        public string Name { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual ICollection<UserSessionEntity> UserSignIns { get; set; }
    }
}
