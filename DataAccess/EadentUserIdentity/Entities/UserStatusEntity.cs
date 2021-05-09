using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Eadent.Identity.Definitions;

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

        public string Name { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public virtual ICollection<UserEntity> Users { get; set; }
    }
}
