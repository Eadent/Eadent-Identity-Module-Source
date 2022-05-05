using Eadent.Identity.Definitions;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("UserRoles")]
    public class UserRoleEntity
    {
        [Key]
        public long UserRoleId { get; set; }

        public long UserId { get; set; }

        public Role RoleId { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }

        public virtual RoleEntity Role { get; set; }

        public virtual UserEntity User { get; set; }
    }
}
