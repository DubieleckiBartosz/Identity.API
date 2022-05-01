using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AutoFixture;
using Identity.API.AccountModel;
using Identity.API.Database;
using Identity.API.Interfaces;
using Identity.API.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.AutoMock;

namespace IdentityTests.Services.UserService
{
    public abstract class UserServiceBaseTests : IDisposable
    {
        protected IdentityContext _identityDbContext;
        protected JWTSettings _jwtSettings;
        protected Mock<ILogger<Identity.API.Services.UserService>> _loggerMock;
        protected Mock<UserManager<ApplicationUser>> _userManagerMock;
        protected Mock<RoleManager<IdentityRole>> _roleManagerMock;
        protected Mock<IEmailService> _emailService;
        protected Mock<IUserService> _userServiceMock;
        protected Identity.API.Services.UserService _userService;
        protected Fixture _fixture;
        protected AutoMocker _mocker;

        public UserServiceBaseTests()
        {
            this._fixture = new Fixture();
            this._mocker = new AutoMocker();
            var options = new DbContextOptionsBuilder<IdentityContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString()).Options;
            this._identityDbContext = new IdentityContext(options);
            this._identityDbContext.Database.EnsureCreated();
            Initialize(_identityDbContext);
            this._jwtSettings = _fixture.Build<JWTSettings>().Create();
            this._loggerMock = _mocker.GetMock<ILogger<Identity.API.Services.UserService>>();
            this._userManagerMock = _mocker.GetMock<UserManager<ApplicationUser>>();
            this._roleManagerMock = _mocker.GetMock<RoleManager<IdentityRole>>();
            this._emailService = _mocker.GetMock<IEmailService>();
            this._userServiceMock = _mocker.GetMock<IUserService>();
            this._mocker.Use(_identityDbContext);
            this._mocker.Use(_jwtSettings);
            this._userService = _mocker.CreateInstance<Identity.API.Services.UserService>();
        }

        protected List<Claim> GetClaims()
        {
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, _fixture.Create<string>()),
                new Claim(ClaimTypes.NameIdentifier, _fixture.Create<string>()),
                new Claim(ClaimTypes.Email, _fixture.Create<string>()),
                new Claim(JwtRegisteredClaimNames.Jti, _fixture.Create<string>()),
            };
            return claims;
        }
        public void Dispose()
        {
            this._identityDbContext.Database.EnsureDeleted();
            this._identityDbContext.Dispose();
        }

        private void Initialize(IdentityContext context)
        {
            context.Users.AddRange(_fixture.Build<ApplicationUser>().CreateMany(100));
            context.SaveChanges();
        }
    }
}
