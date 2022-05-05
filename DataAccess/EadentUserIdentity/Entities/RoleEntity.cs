using Eadent.Identity.Definitions;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("Roles")]
    public class RoleEntity
    {
        public RoleEntity()
        {
            UserRoles = new HashSet<UserRoleEntity>();
        }

        [Key]
        public Role RoleId { get; set; }

        public short RoleLevel { get; set; }

        public string RoleName { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }

        public virtual ICollection<UserRoleEntity> UserRoles { get; set; }
    }
}
