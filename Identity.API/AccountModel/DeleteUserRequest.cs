namespace Identity.API.AccountModel
{
    public class DeleteUserRequest
    {
        public string UserEmail { get; set; }
        public string Password { get; set; }
    }
}