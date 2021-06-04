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
        }

        [Key]
        public PasswordVersion PasswordVersionId { get; set; }

        public string Name { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }
    }
}
