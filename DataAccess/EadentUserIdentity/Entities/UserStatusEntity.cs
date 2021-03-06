using Eadent.Identity.Definitions;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("UserStatuses")]
    public class UserStatusEntity
    {
        public UserStatusEntity()
        {
            Users = new HashSet<UserEntity>();
        }

        [Key]
        public UserStatus UserStatusId { get; set; }

        public string Status { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }

        public virtual ICollection<UserEntity> Users { get; set; }
    }
}
