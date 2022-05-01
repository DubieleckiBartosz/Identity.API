using FluentValidation;
using Identity.API.AccountModel;

namespace Identity.API.Validators
{
    public class ForgotPasswordRequestValidator : AbstractValidator<ForgotPasswordRequest>
    {
        public ForgotPasswordRequestValidator()
        {
            RuleFor(r => r.Email).NotEmpty().EmailAddress();
        }
    }
}