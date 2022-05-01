using FluentValidation;

namespace Identity.API.Validators
{
    public static class BuilderValidators
    {
        public static IRuleBuilderOptions<T, string> PasswordValidator<T>(this IRuleBuilder<T, string> ruleBuilder)
        {
            return DefaultValidatorExtensions.NotEmpty(ruleBuilder).Length(6, 450)
                .Matches("[A-Z]")
                .Matches("[a-z]")
                .Matches("[0-9]")
                .Matches("[^a-zA-Z0-9]");
        }

        public static IRuleBuilderOptions<T, string> EmailValidator<T>(this IRuleBuilder<T, string> ruleBuilder)
        {
            return DefaultValidatorExtensions.NotEmpty(ruleBuilder).WithMessage("Email is required.")
                .EmailAddress()
                .WithMessage("Invalid email format.");
        }
    }
}