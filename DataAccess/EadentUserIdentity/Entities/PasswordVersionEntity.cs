using Eadent.Identity.Definitions;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

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

        public string PasswordVersion { get; set; }

        public DateTime CreatedDateTimeUtc { get; set; }

        public DateTime? LastUpdatedDateTimeUtc { get; set; }
    }
}
