using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Identity.API.AccountModel;
using Identity.API.Enums;
using Identity.API.Interfaces;
using Identity.API.Strings;
using Identity.API.Wrapper;
using Microsoft.AspNetCore.Authorization;

namespace Identity.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IUserService _userService;

        public AccountController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary>
        /// Register user
        /// </summary>
        /// <param name="registerModel"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpPost(Name = "RegisterUser")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest registerModel)
        {
            var result = await _userService.RegisterUserAsync(registerModel, Request.Headers["origin"]);
            return Ok(result);
        }

        /// <summary>
        /// Login user
        /// </summary>
        /// <param name="loginModel"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status206PartialContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(BaseResponse<AuthenticationModel>), 200)]
        [HttpPost("[action]")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginModel)
        {
            var result = await _userService.LoginUserAsync(loginModel, ipAddress());
            if (result.Success is true)
            {
                if (!string.IsNullOrEmpty(result.Data.RefreshToken))
                {
                    SetTokenCookie(result.Data.RefreshToken);
                    return Ok(result);
                }
                else
                {
                    return StatusCode(206, new { Token = $"{result.Data.Token}" });
                }
            }

            return BadRequest(result);
        }

        /// <summary>
        /// Create new role for user
        /// </summary>
        /// <param name="addToRoleModel"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpPost("[action]")]
        public async Task<IActionResult> AddToRole([FromBody] CreateRoleRequest addToRoleModel)
        {
            var result = await _userService.AddRoleToUserAsync(addToRoleModel);
            return Ok(result);
        }

        /// <summary>
        /// Send email with code
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest model)
        {
            var result = await _userService.ForgotPasswordAsync(model);
            return Ok(result);
        }

        /// <summary>
        /// Reset password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
        {
            var result = await _userService.ResetPasswordAsync(model);
            return Ok(result);
        }

        /// <summary>
        /// Confirm new account
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpGet("confirm-account")]
        public async Task<IActionResult> ConfirmAccount([FromQuery] string userId, [FromQuery] string code)
        {
            var result = await _userService.ConfirmAccountAsync(userId, code);
            return Ok(result);
        }

        /// <summary>
        /// Refresh token
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = await _userService.RefreshTokenAsync(refreshToken, ipAddress());

            SetTokenCookie(response.Data.RefreshToken);

            return Ok(response);
        }

        /// <summary>
        /// Revoke token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [ProducesResponseType(typeof(BaseResponse<string>), 400)]
        [ProducesResponseType(typeof(BaseResponse<AuthenticationModel>), 200)]
        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest model)
        {
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(BaseResponse<string>.Error(AuthResponseStrings.TokenRequired));

            var response = await _userService.RevokeTokenAsync(token, ipAddress());

            return Ok(response);
        }

        /// <summary>
        /// Delete User
        /// </summary>
        /// <param name="deleteModel"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpDelete("delete-user")]
        public async Task<IActionResult> DeleteUser([FromBody] DeleteUserRequest deleteModel)
        {
            var result = await _userService.DeleteUserAccountAsync(deleteModel);
            return Ok(result);
        }

        /// <summary>
        /// Get user refresh tokens
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        [Authorize]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(BaseResponse<string>), 200)]
        [HttpGet("[action]/{userId}")]
        public async Task<IActionResult> GetRefreshTokens([FromRoute] string userId)
        {
            if (!this.CheckAccess())
            {
                return BadRequest(BaseResponse<string>.Error(AuthResponseStrings.NotAuthorized));
            }

            var result = await _userService.GetTokens(userId);
            return Ok(result);
        }

        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.Now.AddDays(1)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private bool CheckAccess() => this.User.IsInRole(Roles.Admin.ToString());

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
