using System.Threading.Tasks;
using Identity.API.Exceptions;
using Identity.API.Strings;
using Microsoft.AspNetCore.Identity;
using Moq;
using Xunit;
using AutoFixture;
using Identity.API.AccountModel;

namespace IdentityTests.Services.UserService
{
    public class ResetPassword : UserServiceBaseTests
    {
        [Fact]
        public async Task Should_Throw_Exception_When_User_by_Email_Not_Found()
        {
            var resetPasswordModel = _fixture.Create<ResetPasswordRequest>();
            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(() => null);
            var result = await Assert.ThrowsAsync<IdentityException>(() =>
                _userService.ResetPasswordAsync(resetPasswordModel));
            Assert.Equal(AuthResponseStrings.UserNotRegistered(resetPasswordModel.Email), result.Message);
        }

        [Fact]
        public async Task Should_Throw_IdentityException_When_ResetPassword_Failed()
        {
            var resetPasswordModel = _fixture.Create<ResetPasswordRequest>();
            var user = _fixture.Create<ApplicationUser>();
            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            _userManagerMock
                .Setup(s => s.ResetPasswordAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError()
                {
                    Description = _fixture.Create<string>()
                }));
            var result = await Assert.ThrowsAsync<IdentityException>(() =>
                _userService.ResetPasswordAsync(resetPasswordModel));
            Assert.Equal(AuthResponseStrings.PasswordChangeFailed, result.Message);
        }

        [Fact]
        public async Task Should_ResetPassword_Positive()
        {
            var resetPasswordModel = _fixture.Create<ResetPasswordRequest>();
            var user = _fixture.Create<ApplicationUser>();
            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync(user);
            _userManagerMock
                .Setup(s => s.ResetPasswordAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);
            var result = await _userService.ResetPasswordAsync(resetPasswordModel);
            Assert.True(result.Success);
        }
    }
}
