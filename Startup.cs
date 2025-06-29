using Eadent.Identity.Access;
using Eadent.Identity.Configuration;
using Eadent.Identity.DataAccess.EadentUserIdentity.Databases;
using Eadent.Identity.DataAccess.EadentUserIdentity.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Eadent.Identity
{
    public static class Startup
    {
        public static void ConfigureServices(IServiceCollection services)
        {
            var databaseSettings = EadentIdentitySettings.Instance.UserIdentity.Database;

            string connectionString = $"Server={databaseSettings.DatabaseServer};Database={databaseSettings.DatabaseName};Application Name={databaseSettings.ApplicationName};User Id={databaseSettings.UserName};Password={databaseSettings.Password};Encrypt=false;";

            services.AddDbContext<EadentUserIdentityDatabase>(options => options.UseSqlServer(connectionString));

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
