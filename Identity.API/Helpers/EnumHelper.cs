using System;
using System.Linq;

namespace Identity.API.Helpers
{
    public class EnumHelper
    {
        public static bool EnumExistByString<T>(string value)
        {
            var exists = Enum.GetNames(typeof(T)).Any(x => x.ToLower() == value.ToLower());
            if (exists)
            {
                return true;
            }

            return false;
        }

        public static (T, bool) GetEnumByString<T>(string value)
        {
            var exist = EnumExistByString<T>(value);

            if (!exist)
            {
                return (default, false);
            }

            var enumValue = Enum.GetValues(typeof(T)).Cast<T>()
                .FirstOrDefault(x => x.ToString().ToLower() == value.ToLower());

            return (enumValue, true);
        }
    }
}