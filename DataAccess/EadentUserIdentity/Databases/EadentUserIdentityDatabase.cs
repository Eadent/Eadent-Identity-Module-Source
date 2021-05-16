using Eadent.Common.DataAccess.EntityFramework.Databases;
using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Eadent.Identity.DataAccess.EadentUserIdentity.Databases
{
    internal class EadentUserIdentityDatabase : BaseDatabase, IEadentUserIdentityDatabase
    {
        // Attributes/Properties.
        private EadentIdentitySettings EadentIdentitySettings { get; }

        // Database Tables.
        public virtual DbSet<UserEntity> Users { get; set; }

        public virtual DbSet<UserEMailEntity> UserEMails { get; set; }

        public virtual DbSet<UserRoleEntity> UserRoles { get; set; }

        public virtual DbSet<UserStatusEntity> UserStatuses { get; set; }

        public virtual DbSet<UserAuditEntity> UserAudits { get; set; }

        public virtual DbSet<RoleEntity> Roles { get; set; }

        public virtual DbSet<UserSessionEntity> UserSessions { get; set; }

        public virtual DbSet<SignInStatusEntity> SignInStatuses { get; set; }

        public virtual DbSet<UserPasswordResetEntity> UserPasswordResets { get; set; }

        public virtual DbSet<PasswordVersionEntity> PasswordVersions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasDefaultSchema(EadentIdentitySettings.UserIdentity.Database.DatabaseSchema);

            base.OnModelCreating(modelBuilder);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
        }

        public EadentUserIdentityDatabase(IConfiguration configuration, DbContextOptions<EadentUserIdentityDatabase> options) : base(options)
        {
            EadentIdentitySettings = configuration.GetSection(EadentIdentitySettings.SectionName).Get<EadentIdentitySettings>();

            DatabaseName = EadentIdentitySettings.UserIdentity.Database.DatabaseName;
            DatabaseSchema = EadentIdentitySettings.UserIdentity.Database.DatabaseSchema;
        }
    }
}
