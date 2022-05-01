using System;
using System.Linq;
using System.Threading.Tasks;
using Identity.API.Exceptions;
using Identity.API.Strings;
using Moq;
using Xunit;
using AutoFixture;
using Identity.API.AccountModel;

namespace IdentityTests.Services.UserService
{
    public class RefreshTokenModel : UserServiceBaseTests
    {
        [Fact]
        public async Task Should_Throw_Exception_When_User_Not_Found()
        {
            var result = await Assert.ThrowsAsync<IdentityException>(() =>
                _userService.RefreshTokenAsync(_fixture.Create<string>(), _fixture.Create<string>()));
            Assert.NotEmpty(result.Message);
        }

        [Fact]
        public async Task Should_Throw_Exception_When_Token_Not_Active()
        {
            var tokens = _fixture.Build<RefreshToken>().With(w => w.Revoked, DateTime.Now).CreateMany().ToList();

            var user = _fixture.Build<ApplicationUser>().With(w => w.RefreshTokens, tokens).Create();
            _identityDbContext.Add(user);
            _identityDbContext.SaveChanges();

            var result = await Assert.ThrowsAsync<IdentityException>(() =>
                _userService.RefreshTokenAsync(tokens.First().Token, _fixture.Create<string>()));
            Assert.Equal(AuthResponseStrings.TokenNotActive, result.Message);
        }

        [Fact]
        public async Task Should_Return_Response_With_Model()
        {
            var roles = _fixture.CreateMany<string>().ToList();
            var ipAddress = _fixture.Create<string>();
            var tokens = _fixture.Build<RefreshToken>()
                .Without(w => w.Revoked).With(w => w.Created, DateTime.Now)
                .With(w => w.Expires, DateTime.Now.AddDays(1))
                .CreateMany().ToList();

            var _cntRefreshTokensBefore = tokens.Count;
            var user = _fixture.Build<ApplicationUser>().With(w => w.RefreshTokens, tokens).Create();

            _identityDbContext.Add(user);
            _identityDbContext.SaveChanges();

            _userManagerMock.Setup(s => s.GetRolesAsync(It.IsAny<ApplicationUser>()))
                .ReturnsAsync(roles);
            _userManagerMock.Setup(s => s.GetClaimsAsync(It.IsAny<ApplicationUser>()))
                .ReturnsAsync(GetClaims());

            var result = await _userService.RefreshTokenAsync(tokens.First().Token, ipAddress);

            var account = _identityDbContext.Users.FirstOrDefault(w => w.Email == user.Email);
            var _cntRefreshTokensAfter = account.RefreshTokens.Count;

            Assert.NotNull(result.Data);
            Assert.True(result.Success);
            Assert.Equal(_cntRefreshTokensBefore + 1, _cntRefreshTokensAfter);
        }
    }
}