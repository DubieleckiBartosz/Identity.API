using System;
using System.Collections.Generic;
using Identity.API.Enums;

namespace Identity.API.Client.Models
{
    public class Email
    {
        public string TemplateName { get; }
        public string TemplateType { get; }
        public string SubjectMail { get; }
        public Dictionary<string, string> DictionaryData { get; }
        public List<string> Recipients { get; }

        public Email(List<string> recipients, Dictionary<string, string> dictionaryData,
            string subjectMail, TemplateType templateType, TemplateName templateName)
        {
            this.DictionaryData = dictionaryData ?? throw new ArgumentNullException(nameof(dictionaryData));
            this.Recipients = recipients ?? throw new ArgumentNullException(nameof(recipients));
            this.SubjectMail = subjectMail ?? throw new ArgumentNullException(nameof(subjectMail));
            this.TemplateName = templateName.ToString();
            this.TemplateType = templateType.ToString();
        }
    }
}