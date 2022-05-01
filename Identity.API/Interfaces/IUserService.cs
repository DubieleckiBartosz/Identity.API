using System.Collections.Generic;
using System.Threading.Tasks;
using Identity.API.AccountModel;
using Identity.API.Wrapper;

namespace Identity.API.Interfaces
{
    public interface IUserService
    {
        Task<BaseResponse<string>> RegisterUserAsync(RegisterRequest request, string origin);
        Task<BaseResponse<string>> ConfirmAccountAsync(string userId, string code);
        Task<BaseResponse<AuthenticationModel>> LoginUserAsync(LoginRequest loginModel, string ipAddress);
        Task<BaseResponse<string>> AddRoleToUserAsync(CreateRoleRequest model);
        Task<BaseResponse<AuthenticationModel>> RefreshTokenAsync(string token, string ipAddress);
        Task<BaseResponse<string>> RevokeTokenAsync(string token, string ipAddress);
        Task<BaseResponse<string>> DeleteUserAccountAsync(DeleteUserRequest request);
        Task<BaseResponse<string>> ForgotPasswordAsync(ForgotPasswordRequest model);
        Task<BaseResponse<string>> ResetPasswordAsync(ResetPasswordRequest resetPasswordModel);
        Task<BaseResponse<List<UserBaseModel>>> GetUsersByParametersAsync();
        Task<BaseResponse<IEnumerable<RefreshToken>>> GetTokens(string userId);
        Task<bool> TokenIsActiveAsync(string token);
    }
}