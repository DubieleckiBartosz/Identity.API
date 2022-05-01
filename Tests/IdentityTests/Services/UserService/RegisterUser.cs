using System.Linq;
using System.Threading.Tasks;
using Identity.API.Exceptions;
using Microsoft.AspNetCore.Identity;
using Moq;
using AutoFixture;
using Identity.API.AccountModel;
using Xunit;

namespace IdentityTests.Services.UserService
{
    public class RegisterUser : UserServiceBaseTests
    {
        [Fact]
        public async Task Should_Return_Error_When_User_Exist()
        {
            var origin = _fixture.Create<string>();
            var request = _fixture.Build<RegisterRequest>().Create();
            var user = _fixture.Build<ApplicationUser>().Create();

            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(user);
            var result = await _userService.RegisterUserAsync(request, origin);

            Assert.False(result.Success);
            _userManagerMock.Verify(v => v.FindByNameAsync(It.IsAny<string>()),
                Times.Never);
        }

        [Fact]
        public async Task Should_Return_Error_When_UserName_Exist()
        {
            var origin = _fixture.Create<string>();
            var request = _fixture.Build<RegisterRequest>().Create();
            var applicationUser = _fixture.Build<ApplicationUser>().Create();

            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            _userManagerMock.Setup(s => s.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync(applicationUser);

            var result = await _userService.RegisterUserAsync(request, origin);

            Assert.False(result.Success);
            _userManagerMock.Verify(v => v.FindByNameAsync(It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task Should_Throw_IdentityException_When_Create_New_User_Failed()
        {
            var origin = _fixture.Create<string>();
            var request = _fixture.Build<RegisterRequest>().Create();

            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            _userManagerMock.Setup(s => s.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            _userManagerMock.Setup(c => c.CreateAsync(It.IsAny<ApplicationUser>(),
                    It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError()
                {
                    Description = _fixture.Create<string>()
                }));

            var result =
                await Assert.ThrowsAsync<IdentityException>(() => _userService.RegisterUserAsync(request,
                    origin));
            Assert.True(result.Errors.Any());
        }

        [Fact]
        public async Task Should_Throw_IdentityException_When_Attempt_To_Add_Role_To_User_Has_Failed()
        {
            var origin = _fixture.Create<string>();
            var request = _fixture.Build<RegisterRequest>().Create();

            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            _userManagerMock.Setup(s => s.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            _userManagerMock.Setup(c => c.CreateAsync(It.IsAny<ApplicationUser>(),
                    It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);

            _userManagerMock.Setup(c => c.AddToRoleAsync(It.IsAny<ApplicationUser>(),
                    It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError()
                {
                    Description = _fixture.Create<string>()
                }));

            var result =
                await Assert.ThrowsAsync<IdentityException>(() => _userService.RegisterUserAsync(request, origin));
            _userManagerMock.Verify(v => v.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Once);
            Assert.True(result.Errors.Any());
        }


        [Fact]
        public async Task Should_Return_Response_Ok()
        {
            var origin = "https://localhost:0000";
            var request = _fixture.Build<RegisterRequest>().Create();
            var token = _fixture.Build<string>().Create();

            _userManagerMock.Setup(s => s.FindByEmailAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            _userManagerMock.Setup(s => s.FindByNameAsync(It.IsAny<string>()))
                .ReturnsAsync(() => null);
            _userManagerMock.Setup(c => c.CreateAsync(It.IsAny<ApplicationUser>(),
                    It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);

            _userManagerMock.Setup(c => c.AddToRoleAsync(It.IsAny<ApplicationUser>(),
                    It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);
            _userManagerMock.Setup(s => s.GenerateEmailConfirmationTokenAsync(It.IsAny<ApplicationUser>()))
                .ReturnsAsync(token);

            var result = await _userService.RegisterUserAsync(request, origin);

            Assert.True(result.Success);
        }
    }
}
