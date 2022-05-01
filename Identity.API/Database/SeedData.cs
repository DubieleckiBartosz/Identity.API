using System.Threading.Tasks;
using Identity.API.AccountModel;
using Identity.API.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Identity.API.Database
{
    public class SeedData
    {
        public static async Task GetSeedDataAsync(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            await roleManager.CreateAsync(new IdentityRole(Roles.Admin.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.Manager.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.User.ToString()));
            var usersAlreadyExist = await userManager.Users.AnyAsync();
            if (!usersAlreadyExist)
            {
                var superUser = new ApplicationUser()
                {
                    UserName = "Barti",
                    FirstName = "Bartosz",
                    LastName = "Dubielecki",
                    Email = "Bdubielecki@gmail.com",
                    EmailConfirmed = true
                };
                await userManager.CreateAsync(superUser, "Barti$123");
            }
        }
    }
}