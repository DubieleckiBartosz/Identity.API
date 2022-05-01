using System.Linq;
using System.Net;
using Identity.API.Exceptions;
using Microsoft.AspNetCore.Identity;

namespace Identity.API.Helpers
{
    public static class CheckIdentityResult
    {
        public static void CheckResult(this IdentityResult result, string message = null,
            HttpStatusCode code = HttpStatusCode.BadRequest)
        {
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(s => s.Description);
                throw new IdentityException(message, code, errors);
            }
        }
    }
}