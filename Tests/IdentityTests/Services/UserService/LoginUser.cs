using System.Linq;
using System.Threading.Tasks;
using Moq;
using Xunit;
using AutoFixture;
using Identity.API.AccountModel;

namespace IdentityTests.Services.UserService
{
    public class LoginUser : UserServiceBaseTests
    {
        [Fact]
        public async Task Should_Be_Success_False_When_UserEmail_Does_not_Exist()
        {
            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            var result =
                await _userService.LoginUserAsync(_fixture.Build<LoginRequest>().Create(),
                    _fixture.Create<string>());

            _userManagerMock.Verify(v => v.CheckPasswordAsync(It.IsAny<ApplicationUser>(),
                    It.IsAny<string>()), Times.Never);
            Assert.False(result.Success);
        }

        [Fact]
        public async Task Should_Return_False_When_Password_Is_Not_Correct()
        {
            var user = _fixture.Build<ApplicationUser>().Create();
            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(user);
            _userManagerMock.Setup(s => s.CheckPasswordAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
                .ReturnsAsync(() => false);

            var result =
                await _userService.LoginUserAsync(_fixture.Build<LoginRequest>().Create(),
                    _fixture.Create<string>());

            _userManagerMock.Verify(v => v.CheckPasswordAsync(It.IsAny<ApplicationUser>(),
                It.IsAny<string>()), Times.Once);
            Assert.False(result.Success);
        }

        [Fact]
        public async Task Should_Return_Model_With_Token()
        {
            var user = _identityDbContext.Users.First();
            var roles = _fixture.CreateMany<string>().ToList();
            var loginRequest = _fixture.Build<LoginRequest>().Create();

            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(user);
            _userManagerMock.Setup(s => s.CheckPasswordAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
                .ReturnsAsync(() => true);
            _userManagerMock.Setup(s => s.GetRolesAsync(It.IsAny<ApplicationUser>()))
                .ReturnsAsync(roles);
            _userManagerMock.Setup(s => s.GetClaimsAsync(It.IsAny<ApplicationUser>()))
                .ReturnsAsync(GetClaims());

            var result = await _userService.LoginUserAsync(loginRequest,
                _fixture.Create<string>());

            Assert.NotEmpty(result.Data.Token);
            Assert.True(result.Success);
        }
    }
}
