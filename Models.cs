using System.Collections.Generic;

namespace SystemHardwareAudit.Models
{
    public class AuditCategory
    {
        public string Name { get; set; }
        public List<AuditItem> Items { get; set; } = new List<AuditItem>();
    }

    public class AuditItem
    {
        public string Label { get; set; }
        public string Value { get; set; }
        public string TooltipText { get; set; }
        public bool IsSeparator { get; set; }
        public bool IsPlaceholder { get; set; }
    }
}

