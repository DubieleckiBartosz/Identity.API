using FluentValidation;
using Identity.API.AccountModel;

namespace Identity.API.Validators
{
    public class LoginRequestValidator : AbstractValidator<LoginRequest>
    {
        public LoginRequestValidator()
        {
            RuleFor(r => r.UserEmail).NotEmpty().EmailAddress();
            RuleFor(r => r.UserPassword).NotEmpty();
        }
    }
}