namespace Identity.API.Strings
{
    public static class AuthResponseStrings
    {
        public const string AccountCannotbeCreated = "You can't create an account.";

        public const string MessageAfterCreatingAccount =
            "We sent an email to confirm the creation of an account in our application.";

        public static string PasswordChangeFailed = "An error occurred while resetting the password.";
        public static string PasswordChanged = "Password reset successful, you can now login.";
        public const string MessageForgotPassword = "We sent an email with code to create new password.";
        public const string ErrorConfirmAccount = "Error while confirming the account.";
        public const string RoleNotExist = "Role does not exist.";
        public const string TokenNotActive = "Token is not active.";
        public static string TokenRequired = "Token is required.";
        public static string TokenRevoked = "Token revoked.";
        public static string UserDeleted = "User deleted";
        public static string UserIdIsNullOrEmpty = "Incorrect data! UserId is null or empty.";
        public static string UserNotFound = "Data not found.";
        public static string NotAuthorized = "You are not authorized for this operation.";
        public static string RefreshTokenMessageException = "You cannot refresh the token. Please log in again";
        public static string AccountConfirmedMessage(string name)
        {
            return $"Account Confirmed for {name}.";
        }

        public static string IncorrectDataMessage(string data)
        {
            return $"Incorrect Credentials for user {data}.";
        }

        public static string UserNotFoundMessage(string dataToMessage)
        {
            return $"{dataToMessage} not found.";
        }

        public static string AddedRoleMessage(string role, string email)
        {
            return $"Added {role} to user {email}.";
        }

        public static string UserNotRegistered(string data)
        {
            return $"No Accounts Registered with {data}.";
        }
    }
}
