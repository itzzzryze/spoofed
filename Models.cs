using System.Collections.Generic;
using System.Linq;

namespace SystemHardwareAudit.Models
{
    public class AuditCategory
    {
        public string Name { get; set; }
        public List<AuditItem> Items { get; set; } = new List<AuditItem>();
        public int DisplayItemCount => Items.Count(item => !item.IsSeparator);
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

