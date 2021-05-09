using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

#nullable disable

namespace Eadent.Identity.ScaffoldDbContextModels
{
    public partial class RaptureTherapyContext : DbContext
    {
        public RaptureTherapyContext()
        {
        }

        public RaptureTherapyContext(DbContextOptions<RaptureTherapyContext> options)
            : base(options)
        {
        }

        public virtual DbSet<PasswordReset> PasswordResets { get; set; }
        public virtual DbSet<PasswordVersion> PasswordVersions { get; set; }
        public virtual DbSet<RaptureTherapyDatabaseVersion> RaptureTherapyDatabaseVersions { get; set; }
        public virtual DbSet<Role> Roles { get; set; }
        public virtual DbSet<SignInStatus> SignInStatuses { get; set; }
        public virtual DbSet<User> Users { get; set; }
        public virtual DbSet<UserAudit> UserAudits { get; set; }
        public virtual DbSet<UserEmail> UserEmails { get; set; }
        public virtual DbSet<UserRole> UserRoles { get; set; }
        public virtual DbSet<UserSession> UserSessions { get; set; }
        public virtual DbSet<UserStatus> UserStatuses { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
                optionsBuilder.UseSqlServer("Server=77.68.93.167;Database=RaptureTherapy;User Id=sa;Password=Oper@tionJenn!fer2@2!;");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasAnnotation("Relational:Collation", "SQL_Latin1_General_CP1_CI_AS");

            modelBuilder.Entity<PasswordReset>(entity =>
            {
                entity.ToTable("PasswordResets", "Dad_Identity");

                entity.Property(e => e.EmailAddress)
                    .IsRequired()
                    .HasMaxLength(256)
                    .HasColumnName("EMailAddress");

                entity.Property(e => e.IpAddress)
                    .IsRequired()
                    .HasMaxLength(128);

                entity.Property(e => e.ResetToken)
                    .IsRequired()
                    .HasMaxLength(256);

                entity.HasOne(d => d.User)
                    .WithMany(p => p.PasswordResets)
                    .HasForeignKey(d => d.UserId)
                    .HasConstraintName("FK_Dad_Identity_PasswordResets_Users");
            });

            modelBuilder.Entity<PasswordVersion>(entity =>
            {
                entity.ToTable("PasswordVersions", "Dad_Identity");

                entity.Property(e => e.PasswordVersionId).ValueGeneratedNever();

                entity.Property(e => e.CreatedDateTimeUtc).HasDefaultValueSql("(getutcdate())");

                entity.Property(e => e.Description)
                    .IsRequired()
                    .HasMaxLength(128);
            });

            modelBuilder.Entity<RaptureTherapyDatabaseVersion>(entity =>
            {
                entity.HasKey(e => e.DatabaseVersionId)
                    .HasName("PK_Dad_Identity_RaptureTherapyDatabaseVersions");

                entity.ToTable("RaptureTherapyDatabaseVersions", "Dad_Identity");

                entity.Property(e => e.Description)
                    .IsRequired()
                    .HasMaxLength(128);
            });

            modelBuilder.Entity<Role>(entity =>
            {
                entity.ToTable("Roles", "Dad_Identity");

                entity.Property(e => e.RoleId).ValueGeneratedNever();

                entity.Property(e => e.CreatedDateTimeUtc).HasDefaultValueSql("(getutcdate())");

                entity.Property(e => e.Description)
                    .IsRequired()
                    .HasMaxLength(128);
            });

            modelBuilder.Entity<SignInStatus>(entity =>
            {
                entity.ToTable("SignInStatuses", "Dad_Identity");

                entity.Property(e => e.SignInStatusId).ValueGeneratedNever();

                entity.Property(e => e.CreatedDateTimeUtc).HasDefaultValueSql("(getutcdate())");

                entity.Property(e => e.Description)
                    .IsRequired()
                    .HasMaxLength(128);
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("Users", "Dad_Identity");

                entity.HasIndex(e => e.UserGuid, "IX_Dad_Identity_User_UserGuid");

                entity.Property(e => e.DisplayName)
                    .IsRequired()
                    .HasMaxLength(256);

                entity.Property(e => e.Password)
                    .IsRequired()
                    .HasMaxLength(256)
                    .UseCollation("SQL_Latin1_General_CP1_CS_AS");

                entity.HasOne(d => d.PasswordVersion)
                    .WithMany(p => p.Users)
                    .HasForeignKey(d => d.PasswordVersionId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Dad_Identity_Users_PasswordVersions");

                entity.HasOne(d => d.UserStatus)
                    .WithMany(p => p.Users)
                    .HasForeignKey(d => d.UserStatusId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Dad_Identity_Users_UserStatuses");
            });

            modelBuilder.Entity<UserAudit>(entity =>
            {
                entity.ToTable("UserAudits", "Dad_Identity");

                entity.HasIndex(e => e.UserId, "IX_Dad_Identity_UserAudits_UserId");

                entity.Property(e => e.Description)
                    .IsRequired()
                    .HasMaxLength(256);

                entity.Property(e => e.IpAddress)
                    .IsRequired()
                    .HasMaxLength(128);

                entity.Property(e => e.NewValue).HasMaxLength(256);

                entity.Property(e => e.OldValue).HasMaxLength(256);

                entity.HasOne(d => d.User)
                    .WithMany(p => p.UserAudits)
                    .HasForeignKey(d => d.UserId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Dad_Identity_UserAudits_Users");
            });

            modelBuilder.Entity<UserEmail>(entity =>
            {
                entity.ToTable("UserEMails", "Dad_Identity");

                entity.HasIndex(e => e.EmailAddress, "IX_Dad_Identity_UserEMails_EMailAddress");

                entity.HasIndex(e => new { e.UserId, e.EmailAddress }, "UQ_Dad_Identity_UserEMails_UserId_EMailAddress")
                    .IsUnique();

                entity.Property(e => e.UserEmailId).HasColumnName("UserEMailId");

                entity.Property(e => e.EmailAddress)
                    .IsRequired()
                    .HasMaxLength(256)
                    .HasColumnName("EMailAddress");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.UserEmails)
                    .HasForeignKey(d => d.UserId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Dad_Identity_UserEMails_Users");
            });

            modelBuilder.Entity<UserRole>(entity =>
            {
                entity.ToTable("UserRoles", "Dad_Identity");

                entity.HasIndex(e => e.UserId, "IX_Dad_Identity_UserRoles_UserId");

                entity.Property(e => e.CreatedDateTimeUtc).HasDefaultValueSql("(getutcdate())");

                entity.HasOne(d => d.Role)
                    .WithMany(p => p.UserRoles)
                    .HasForeignKey(d => d.RoleId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Dad_Identity_UserRoles_Roles");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.UserRoles)
                    .HasForeignKey(d => d.UserId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Dad_Identity_UserRoles_Users");
            });

            modelBuilder.Entity<UserSession>(entity =>
            {
                entity.ToTable("UserSessions", "Dad_Identity");

                entity.HasIndex(e => e.UserSessionToken, "IX_Dad_Identity_UserSessions_UserSessionToken");

                entity.Property(e => e.EmailAddress)
                    .IsRequired()
                    .HasMaxLength(256)
                    .HasColumnName("EMailAddress");

                entity.Property(e => e.IpAddress)
                    .IsRequired()
                    .HasMaxLength(128);

                entity.Property(e => e.UserSessionToken)
                    .IsRequired()
                    .HasMaxLength(256);

                entity.HasOne(d => d.SignInStatus)
                    .WithMany(p => p.UserSessions)
                    .HasForeignKey(d => d.SignInStatusId)
                    .OnDelete(DeleteBehavior.ClientSetNull)
                    .HasConstraintName("FK_Dad_Identity_UserSessions_SignInStatuses");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.UserSessions)
                    .HasForeignKey(d => d.UserId)
                    .HasConstraintName("FK_Dad_Identity_UserSessions_Users");
            });

            modelBuilder.Entity<UserStatus>(entity =>
            {
                entity.ToTable("UserStatuses", "Dad_Identity");

                entity.Property(e => e.UserStatusId).ValueGeneratedNever();

                entity.Property(e => e.CreatedDateTimeUtc).HasDefaultValueSql("(getutcdate())");

                entity.Property(e => e.Description)
                    .IsRequired()
                    .HasMaxLength(128);
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
