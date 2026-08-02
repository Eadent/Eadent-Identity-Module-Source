using Eadent.Common.Configuration;
using Eadent.Identity.Access;
using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Eadent.Identity
{
    public static class Startup
    {
        public static void ConfigureServices(IServiceCollection services, Serilog.ILogger logger)
        {
            int eadentIdentityDatabaseTypeValue = EadentIdentitySettings.Instance.UserIdentity.DatabaseTypeValue;

            if (eadentIdentityDatabaseTypeValue == DatabaseType.SqlServer)
            {
                if (logger != null)
                    logger.Information("Using SQL Server for Eadent Identity Database: {DatabaseName}", EadentIdentitySettings.Instance.UserIdentity.SqlServerDatabase.DatabaseName);

                var connectionString = EadentIdentitySettings.Instance.UserIdentity.SqlServerDatabase.ConnectionString;

                services.AddDbContext<EadentUserIdentityDatabase>(options => options.UseSqlServer(connectionString));
            }
            else if (eadentIdentityDatabaseTypeValue == DatabaseType.PostgreSql)
            {
                if (logger != null)
                    logger.Information("Using PostgreSQL for Eadent Identity Database: {DatabaseName}", EadentIdentitySettings.Instance.UserIdentity.PostgreSqlDatabase.DatabaseName);

                var connectionString = EadentIdentitySettings.Instance.UserIdentity.PostgreSqlDatabase.ConnectionString;

                services.AddDbContext<EadentUserIdentityDatabase>(options => options.UseNpgsql(connectionString));
            }
            else
            {
                if (logger != null)
                    logger.Error($"Unsupported Eadent Identity Database Type Value: {eadentIdentityDatabaseTypeValue}");

                throw new InvalidOperationException($"Unsupported Eadent Identity Database Type Value: {eadentIdentityDatabaseTypeValue}");
            }

            services.AddScoped<IEadentUserIdentityDatabase, EadentUserIdentityDatabase>();

            services.AddTransient<IRolesRepository, RolesRepository>();
            services.AddTransient<ISignInStatusesRepository, SignInStatusesRepository>();
            services.AddTransient<IUserAuditsRepository, UserAuditsRepository>();
            services.AddTransient<IUserRolesRepository, UserRolesRepository>();
            services.AddTransient<IUserSignInsRepository, UserSignInsRepository>();
            services.AddTransient<IUsersRepository, UsersRepository>();
            services.AddTransient<IUserStatusesRepository, UserStatusesRepository>();
            services.AddTransient<IUserSessionsRepository, UserSessionsRepository>();
            services.AddTransient<IUserPasswordResetsRepository, UserPasswordResetsRepository>();

            services.AddTransient<IEadentUserIdentity, EadentUserIdentity>();
            services.AddTransient<IEadentWebApiUserIdentity, EadentWebApiUserIdentity>();
        }
    }
}
