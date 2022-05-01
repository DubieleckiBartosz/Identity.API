using System.Threading.Tasks;
using Identity.API.Exceptions;
using Identity.API.Strings;
using Moq;
using Xunit;
using AutoFixture;
using Identity.API.AccountModel;

namespace IdentityTests.Services.UserService
{
    public class ForgotPassword : UserServiceBaseTests
    {
        [Fact]
        public async Task Should_Throw_Exception_When_User_Not_Found()
        {
            var model = _fixture.Create<ForgotPasswordRequest>();
            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            var result = await Assert.ThrowsAsync<IdentityException>(() =>
                _userService.ForgotPasswordAsync(model));
            Assert.Equal(AuthResponseStrings.UserNotFoundMessage(model.Email), result.Message);
        }

        [Fact]
        public async Task Should_Return_Success()
        {
            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(_fixture.Build<ApplicationUser>().Create());
            _userManagerMock.Setup(s => s.GeneratePasswordResetTokenAsync(It.IsAny<ApplicationUser>()))
                .ReturnsAsync(_fixture.Create<string>());

            var result = await _userService.ForgotPasswordAsync(_fixture.Create<ForgotPasswordRequest>());
            Assert.True(result.Success);
        }
    }
}