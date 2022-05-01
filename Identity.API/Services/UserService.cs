using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Identity.API.AccountModel;
using Identity.API.Database;
using Identity.API.Enums;
using Identity.API.Exceptions;
using Identity.API.Helpers;
using Identity.API.Interfaces;
using Identity.API.Settings;
using Identity.API.Strings;
using Identity.API.Wrapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Identity.API.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWTSettings _jwtSettings;
        private readonly ILogger<UserService> _logger;
        private readonly IEmailService _emailService;
        private readonly IdentityContext _dbContext;

        public UserService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            JWTSettings jwtSettings, ILogger<UserService> logger, IEmailService emailService,
            IdentityContext dbContext)
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
            this._jwtSettings = jwtSettings;
            this._logger = logger;
            this._emailService = emailService;
            this._dbContext = dbContext;
        }

        public async Task<BaseResponse<string>> RegisterUserAsync(RegisterRequest request, string origin)
        {
            var userEmailExist = await _userManager.FindByEmailAsync(request.Email);

            if (userEmailExist != null)
            {
                return BaseResponse<string>.Error(AuthResponseStrings.AccountCannotbeCreated);
            }

            var userNameExist = await _userManager.FindByNameAsync(request.UserName);

            if (userNameExist != null)
            {
                return BaseResponse<string>.Error(AuthResponseStrings.AccountCannotbeCreated);
            }

            var user = new ApplicationUser
            {
                FirstName = request.FirstName,
                LastName = request.LastName,
                Email = request.Email,
                UserName = request.UserName
            };

            var resultUser = await _userManager.CreateAsync(user, request.Password);
            resultUser.CheckResult();

            var resultRole = await _userManager.AddToRoleAsync(user, Roles.User.ToString());
            resultRole.CheckResult();

            // await SendVerificationEmailAsync(user, origin);
            return BaseResponse<string>.Ok(AuthResponseStrings.MessageAfterCreatingAccount);
        }


        public async Task<BaseResponse<AuthenticationModel>> LoginUserAsync(LoginRequest loginModel, string ipAddress)
        {
            var user = await _userManager.FindByEmailAsync(loginModel.UserEmail);
            if (user == null)
            {
                return BaseResponse<AuthenticationModel>.Error(
                    AuthResponseStrings.UserNotFoundMessage(loginModel.UserEmail));
            }

            var passwordIsCorrect = await _userManager.CheckPasswordAsync(user, loginModel.UserPassword);
            if (!passwordIsCorrect)
            {
                return BaseResponse<AuthenticationModel>.Error(
                    AuthResponseStrings.IncorrectDataMessage(loginModel.UserEmail));
            }

            (JwtSecurityToken token, List<string> roles) = await GetTokenAsync(user);
            var refreshToken = GenerateRefreshToken(ipAddress);
            user.RefreshTokens.Add(refreshToken);
            removeOldRefreshTokens(user);

            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync();
            var modelResponse = new AuthenticationModel
            {
                UserName = user.UserName,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Roles = roles,
                RefreshToken = refreshToken.Token
            };
            return BaseResponse<AuthenticationModel>.Ok(modelResponse);
        }


        public async Task<BaseResponse<AuthenticationModel>> RefreshTokenAsync(string token, string ipAddress)
        {
            (RefreshToken refreshToken, ApplicationUser user) = await GetRefreshTokenAsync(token, ipAddress);

            var newRefreshToken = GenerateRefreshToken(ipAddress);

            refreshToken.Revoked = DateTime.Now;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);

            removeOldRefreshTokens(user);

            _dbContext.Update(user);
            await _dbContext.SaveChangesAsync();

            (JwtSecurityToken jwtSecurityToken, List<string> roles) = await GetTokenAsync(user);
            var responseModel = new AuthenticationModel
            {
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Roles = roles,
                RefreshToken = newRefreshToken.Token,
                UserName = user.UserName
            };

            return BaseResponse<AuthenticationModel>.Ok(responseModel);
        }

        public async Task<BaseResponse<string>> ForgotPasswordAsync(ForgotPasswordRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            user.WhenNull(AuthResponseStrings.UserNotFoundMessage(model.Email));

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _emailService.SendEmailResetPasswordAsync(user.Email, resetToken);

            return BaseResponse<string>.Ok(AuthResponseStrings.MessageForgotPassword);
        }

        public async Task<BaseResponse<string>> ResetPasswordAsync(ResetPasswordRequest resetPasswordModel)
        {
            var account = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            account.WhenNull(AuthResponseStrings.UserNotRegistered(resetPasswordModel.Email));

            var result =
                await _userManager.ResetPasswordAsync(account, resetPasswordModel.Token, resetPasswordModel.Password);
            result.CheckResult(AuthResponseStrings.PasswordChangeFailed);

            return BaseResponse<string>.Ok(AuthResponseStrings.PasswordChanged);
        }


        public async Task<BaseResponse<string>> DeleteUserAccountAsync(DeleteUserRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.UserEmail);
            user.WhenNull(AuthResponseStrings.UserNotFoundMessage(request.UserEmail));

            var passwordIsCorrect = await _userManager.CheckPasswordAsync(user, request.Password);

            passwordIsCorrect.WhenBadRequest(x => !x,
                AuthResponseStrings.IncorrectDataMessage(request.UserEmail));

            await _userManager.DeleteAsync(user);
            return BaseResponse<string>.Ok(AuthResponseStrings.UserDeleted);
        }

        public async Task<BaseResponse<string>> AddRoleToUserAsync(CreateRoleRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.UserEmail);
            user.WhenNull(AuthResponseStrings.UserNotFoundMessage(model.UserEmail));

            (Roles enumValue, bool success) = EnumHelper.GetEnumByString<Roles>(model.RoleName);
            success.WhenBadRequest(c => c == false, AuthResponseStrings.RoleNotExist);

            var result = await _userManager.AddToRoleAsync(user, enumValue.ToString());
            result.CheckResult();
            return BaseResponse<string>.Ok(AuthResponseStrings.AddedRoleMessage(enumValue.ToString(), user.Email));
        }

        public async Task<BaseResponse<string>> ConfirmAccountAsync(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);
            user.WhenNull(AuthResponseStrings.ErrorConfirmAccount);
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user, code);
            result.CheckResult();

            return BaseResponse<string>.Ok(AuthResponseStrings.AccountConfirmedMessage(user.UserName));
        }

        public async Task<BaseResponse<string>> RevokeTokenAsync(string token, string ipAddress)
        {
            var (refreshToken, user) = await GetRefreshTokenAsync(token, ipAddress);

            refreshToken.Revoked = DateTime.Now;
            refreshToken.RevokedByIp = ipAddress;
            _dbContext.Update(user);
            await _dbContext.SaveChangesAsync();
            return BaseResponse<string>.Ok(AuthResponseStrings.TokenRevoked);
        }


        public Task<BaseResponse<List<UserBaseModel>>> GetUsersByParametersAsync()
        {
            //var users = _userManager.Users;
            //List<UserBaseModel> userlist = new();
            //foreach (var applicationUser in users)
            //{
            //    userlist.Add(new UserBaseModel(){Roles = _userManager.});
            //}

            throw new NotImplementedException();
        }

        public async Task<BaseResponse<IEnumerable<RefreshToken>>> GetTokens(string userId)
        {
            userId.WhenBadRequest(x => string.IsNullOrEmpty(x), AuthResponseStrings.UserIdIsNullOrEmpty);
            var user = await _userManager.FindByIdAsync(userId);
            user.WhenNull(AuthResponseStrings.UserNotFound);
            return BaseResponse<IEnumerable<RefreshToken>>.Ok(user.RefreshTokens);
        }

        public async Task<bool> TokenIsActiveAsync(string token)
        {
            var userId = this.ValidateCurrentToken(token) ??
                         throw new IdentityException(AuthResponseStrings.TokenNotActive, HttpStatusCode.BadRequest);
            var user = await _userManager.FindByIdAsync(userId);
            var activeTokens = user.RefreshTokens.Where(w => w.IsActive);
            if (activeTokens.Any())
            {
                return true;
            }

            return false;
        }


        #region private

        private string ValidateCurrentToken(string token)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Key));

            var myIssuer = _jwtSettings.Issuer;
            var myAudiences = _jwtSettings.Audiences;

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = myIssuer,
                ValidAudiences = myAudiences,
                LifetimeValidator = CustomLifetimeValidator,
                IssuerSigningKey = mySecurityKey
            }, out SecurityToken validatedToken);
            var jwtToken = (JwtSecurityToken)validatedToken;
            var userId = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;

            return userId;
        }

        private bool CustomLifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken token,
            TokenValidationParameters @params)
        {
            if (expires != null && expires > DateTime.UtcNow)
            {
                return true;
            }

            throw new SecurityTokenInvalidLifetimeException("Token time has expired.");
        }

        private async Task<(JwtSecurityToken, List<string>)> GetTokenAsync(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var userClaims = await _userManager.GetClaimsAsync(user);

            var roleClaims = new List<Claim>();
            foreach (var userRole in roles)
            {
                roleClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var audiences = _jwtSettings.Audiences.Select((audience, i) => { return new Claim($"aud{i}", audience); });

            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Name, user.UserName)
                }.Union(roleClaims)
                .Union(userClaims)
                .Union(audiences);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var credentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            return (new JwtSecurityToken(
                signingCredentials: credentials,
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Issuer, // Audience <=> Issuer in this case
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)), roles.ToList());
        }

        private async Task<(RefreshToken, ApplicationUser)> GetRefreshTokenAsync(string token, string ipAddress)
        {
            var user = await _dbContext.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

            user.WhenNull(AuthResponseStrings.RefreshTokenMessageException);
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            refreshToken.WhenBadRequest(v => !v.IsActive, AuthResponseStrings.TokenNotActive,
                HttpStatusCode.Unauthorized);

            return (refreshToken, user);
        }

        private async Task SendVerificationEmailAsync(ApplicationUser userApplication, string origin)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(userApplication);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var routeUri = new Uri(string.Concat($"{origin}/", "api/account/confirm-account/"));
            var verificationUri = QueryHelpers.AddQueryString(routeUri.ToString(), "userId", userApplication.Id);
            verificationUri = QueryHelpers.AddQueryString(verificationUri, "code", code);

            await _emailService.SendEmailAfterCreateNewAccountAsync(userApplication.Email, verificationUri,
                userApplication.UserName);
        }

        private void removeOldRefreshTokens(ApplicationUser user)
        {
            user.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created.AddMinutes(_jwtSettings.DurationInMinutes) <= DateTime.Now);
        }

        private RefreshToken GenerateRefreshToken(string ipAddress)
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.Now.AddDays(1),
                Created = DateTime.Now,
                CreatedByIp = ipAddress
            };
        }

        #endregion
    }
}

