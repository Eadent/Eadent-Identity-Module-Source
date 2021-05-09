using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Eadent.Identity.Definitions;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("PasswordVersions")]
    public class PasswordVersionEntity
    {
        public PasswordVersionEntity()
        {
            Users = new HashSet<UserEntity>();
        }

        [Key]
        public PasswordVersion PasswordVersionId { get; set; }

        public string Name { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual ICollection<UserEntity> Users { get; set; }
    }
}
