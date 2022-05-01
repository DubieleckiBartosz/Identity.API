using FluentValidation;
using Identity.API.AccountModel;

namespace Identity.API.Validators
{
    public class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
    {
        public ResetPasswordRequestValidator()
        {
            RuleFor(r => r.Password).PasswordValidator();
            RuleFor(r => r.Email).EmailValidator();
            RuleFor(c => c.ConfirmPassword).NotEmpty().Equal(x => x.Password)
                .WithMessage("Your passwords are different");
            RuleFor(r => r.Token).NotEmpty();
        }
    }
}