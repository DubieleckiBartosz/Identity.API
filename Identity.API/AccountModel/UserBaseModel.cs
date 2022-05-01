using System.Collections.Generic;

namespace Identity.API.AccountModel
{
    public class UserBaseModel
    {
        public string UserId { get; set; }
        public List<string> Roles { get; set; }
    }
}