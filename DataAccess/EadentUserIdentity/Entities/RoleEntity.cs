using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Eadent.Identity.Definitions;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Entities
{
    [Table("Roles")]
    public class RoleEntity
    {
        // Users having a Role Level <= this value are considered Privileged.
        public const short RoleLevelPrivilegedThresholdInclusive = 3000;

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
