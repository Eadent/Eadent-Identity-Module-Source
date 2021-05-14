namespace Eadent.Identity.Configuration
{
    public class EadentIdentitySettings
    {
        public const string SectionName = "EadentIdentity";

        public class DatabaseSettings
        {
            public string DatabaseServer { get; set; }

            public string DatabaseName { get; set; }

            public string DatabaseSchema { get; set; }

            public string ApplicationName { get; set; }

            public string UserName { get; set; }

            public string Password { get; set; }
        }

        public class SecuritySettings
        {
            public class HasherSettings
            {
                public string SiteSalt { get; set; }

                public int IterationCount { get; set; }

                public int NumDerivedKeyBytes { get; set; }
            }

            public HasherSettings Hasher { get; set; }
        }

        public class AccountSettings
        {
            public int SignInErrorLimit { get; set; }

            public int SignInLockOutDurationSeconds { get; set; }

            public int SessionExpirationDurationSeconds { get; set; }

            public int PasswordResetExpirationDurationSeconds { get; set; }
        }

        public class UserIdentitySettings
        {
            public DatabaseSettings Database { get; set; }

            public SecuritySettings Security { get; set; }

            public AccountSettings Account { get; set; }
        }

        public UserIdentitySettings UserIdentity { get; set; }
    }
}
