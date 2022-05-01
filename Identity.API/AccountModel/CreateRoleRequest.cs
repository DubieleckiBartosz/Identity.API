namespace Identity.API.AccountModel
{
    public class CreateRoleRequest
    {
        public string UserEmail { get; set; }
        public string RoleName { get; set; }
    }
}