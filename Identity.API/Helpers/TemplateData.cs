using System.Collections.Generic;

namespace Identity.API.Helpers
{
    public class TemplateData
    {
        public static Dictionary<string, string> TemplateRegisterAccount(string userName, string code)
        {
            var dictData = new Dictionary<string, string>()
            {
                {"UserName",userName},
                {"VerificationUri",code}
            };
            return dictData;
        }

        public static Dictionary<string, string> TemplateResetPassword(string resetToken)
        {
            var dictData = new Dictionary<string, string>()
            {
                {"resetToken", resetToken}
            };
            return dictData;
        }
    }
}