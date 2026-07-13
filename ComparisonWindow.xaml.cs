using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using SystemHardwareAudit.Models;

namespace SystemHardwareAudit
{
    public enum ComparisonExpectation
    {
        ShouldChange,
        ShouldStayStable,
        Informational
    }

    public enum ComparisonOutcome
    {
        Pass,
        Stable,
        Attention,
        Info,
        Unavailable
    }

    public class ComparisonItem
    {
        public string Category { get; set; } = "";
        public string Label { get; set; } = "";
        public string OldValue { get; set; } = "";
        public string NewValue { get; set; } = "";
        public bool IsChanged { get; set; }
        public bool IsSectionHeader { get; set; }
        public string SectionTitle { get; set; } = "";
        public string SectionSubtitle { get; set; } = "";
        public string SectionTag { get; set; } = "";
        public int SectionCheckCount { get; set; }
        public bool IsGroupHeader { get; set; }
        public string GroupTitle { get; set; } = "";
        public string GroupSubtitle { get; set; } = "";
        public ComparisonExpectation Expectation { get; set; }
        public ComparisonOutcome Outcome { get; set; }
        public string ResultTitle { get; set; } = "";
        public string ResultDetail { get; set; } = "";

        public string ExpectationText => Expectation switch
        {
            ComparisonExpectation.ShouldChange => "Expected to change",
            ComparisonExpectation.ShouldStayStable => "Expected to stay the same",
            _ => "Context only"
        };

        public bool IsPass => Outcome == ComparisonOutcome.Pass;
        public bool IsStable => Outcome == ComparisonOutcome.Stable;
        public bool NeedsAttention => Outcome == ComparisonOutcome.Attention;
        public bool IsInformational => Outcome == ComparisonOutcome.Info;
        public bool IsUnavailable => Outcome == ComparisonOutcome.Unavailable;
        public bool StrikeOldValue => IsChanged && Expectation == ComparisonExpectation.ShouldChange && IsPass;

        public string RowBackground => Outcome switch
        {
            ComparisonOutcome.Pass => "#1534D399",
            ComparisonOutcome.Stable => "#150EA5E9",
            ComparisonOutcome.Attention => "#18F87171",
            ComparisonOutcome.Info => "#125856D6",
            _ => "#14FBBF24"
        };

        public string ResultForeground => Outcome switch
        {
            ComparisonOutcome.Pass => "#FF6EE7B7",
            ComparisonOutcome.Stable => "#FF7DD3FC",
            ComparisonOutcome.Attention => "#FFFCA5A5",
            ComparisonOutcome.Info => "#FFC7D2FE",
            _ => "#FFFCD34D"
        };

        public string ResultBackground => Outcome switch
        {
            ComparisonOutcome.Pass => "#2634D399",
            ComparisonOutcome.Stable => "#260EA5E9",
            ComparisonOutcome.Attention => "#2AF87171",
            ComparisonOutcome.Info => "#245856D6",
            _ => "#26FBBF24"
        };

        public string ResultBorder => Outcome switch
        {
            ComparisonOutcome.Pass => "#3434D399",
            ComparisonOutcome.Stable => "#340EA5E9",
            ComparisonOutcome.Attention => "#34F87171",
            ComparisonOutcome.Info => "#345856D6",
            _ => "#34FBBF24"
        };

        public string CurrentValueForeground => IsChanged
            ? Outcome switch
            {
                ComparisonOutcome.Pass => "#FF6EE7B7",
                ComparisonOutcome.Attention => "#FFFCA5A5",
                _ => "#FFC7D2FE"
            }
            : "#E0FFFFFF";
    }

    public partial class ComparisonWindow : Window, INotifyPropertyChanged
    {
        private const char OccurrenceSeparator = '\u001F';
        private static readonly StringComparer Comparer = StringComparer.OrdinalIgnoreCase;
        private static readonly HashSet<string> TpmLabels = new HashSet<string>(Comparer)
        {
            "TPM Status",
            "Manufacturer ID",
            "Manufacturer Version",
            "Spec Version",
            "Endorsement Key",
            "Endorsement Key Serial Number",
            "Endorsement Key Thumbprint"
        };
        private static readonly HashSet<string> DiskIdentifierLabels = new HashSet<string>(Comparer)
        {
            "STORAGE_QUERY_PROPERTY",
            "SMART_RCV_DRIVE_DATA",
            "STORAGE_QUERY_WWN",
            "SCSI_PASS_THROUGH",
            "ATA_PASS_THROUGH"
        };

        private readonly ObservableCollection<ComparisonItem> _allComparisonItems = new ObservableCollection<ComparisonItem>();
        private readonly ObservableCollection<ComparisonItem> _importantComparisonItems = new ObservableCollection<ComparisonItem>();
        private ObservableCollection<ComparisonItem> _comparisonItems;
        private string _summaryText = "";
        private string _activeScopeDescription = "";

        public ObservableCollection<ComparisonItem> ComparisonItems
        {
            get => _comparisonItems;
            private set
            {
                _comparisonItems = value;
                OnPropertyChanged();
            }
        }

        public int ImportantItemCount => _importantComparisonItems.Count(item => !item.IsSectionHeader);
        public int AllItemCount => _allComparisonItems.Count(item => !item.IsSectionHeader);
        public int PassedCount { get; private set; }
        public int StableCount { get; private set; }
        public int AttentionCount { get; private set; }
        public int UnavailableCount { get; private set; }
        public int InformationalCount { get; private set; }

        public string SummaryText
        {
            get => _summaryText;
            private set
            {
                _summaryText = value;
                OnPropertyChanged();
            }
        }

        public string ActiveScopeDescription
        {
            get => _activeScopeDescription;
            private set
            {
                _activeScopeDescription = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public ComparisonWindow(ObservableCollection<AuditCategory> oldData, ObservableCollection<AuditCategory> currentData)
        {
            _comparisonItems = _importantComparisonItems;
            InitializeComponent();
            DataContext = this;
            BuildComparison(oldData, currentData);
            ShowScope(_importantComparisonItems, "Key spoofing checks");
            ImportantTab.IsChecked = true;
        }

        private void BuildComparison(ObservableCollection<AuditCategory> oldData, ObservableCollection<AuditCategory> currentData)
        {
            var allCategoryNames = GetNormalizedCategoryNames(oldData)
                .Concat(GetNormalizedCategoryNames(currentData))
                .Distinct(Comparer)
                .ToList();

            foreach (string categoryName in allCategoryNames)
            {
                var oldItems = BuildItemMap(GetNormalizedItems(oldData, categoryName));
                var newItems = BuildItemMap(GetNormalizedItems(currentData, categoryName));
                var allKeys = oldItems.Keys.Concat(newItems.Keys).Distinct(Comparer);
                var allCategoryItems = new List<ComparisonItem>();
                var importantCategoryItems = new List<ComparisonItem>();

                foreach (string key in allKeys)
                {
                    oldItems.TryGetValue(key, out AuditItem? oldItem);
                    newItems.TryGetValue(key, out AuditItem? newItem);

                    string label = oldItem?.Label ?? newItem?.Label ?? "";
                    string oldValue = GetComparisonValue(categoryName, oldItem);
                    string newValue = GetComparisonValue(categoryName, newItem);
                    if (string.IsNullOrWhiteSpace(oldValue) && string.IsNullOrWhiteSpace(newValue))
                        continue;

                    int occurrence = GetOccurrence(key);
                    DiskContext? diskContext = Comparer.Equals(categoryName, "Disk Drive Information")
                        ? BuildDiskContext(oldItems, newItems, occurrence)
                        : null;
                    TpmContext? tpmContext = Comparer.Equals(categoryName, "TPM Information")
                        ? BuildTpmContext(oldItems, newItems)
                        : null;

                    ComparisonItem comparisonItem = AssessItem(categoryName, label, oldValue, newValue, occurrence, diskContext, tpmContext);
                    allCategoryItems.Add(comparisonItem);
                    if (IsImportant(categoryName, label))
                    {
                        importantCategoryItems.Add(comparisonItem);
                    }
                }

                AddCategorySection(_allComparisonItems, categoryName, allCategoryItems);
                AddCategorySection(_importantComparisonItems, categoryName, importantCategoryItems);
            }

            OnPropertyChanged(nameof(ImportantItemCount));
            OnPropertyChanged(nameof(AllItemCount));
        }

        private static void AddCategorySection(
            ObservableCollection<ComparisonItem> target,
            string categoryName,
            IReadOnlyCollection<ComparisonItem> items)
        {
            if (items.Count == 0)
                return;

            target.Add(new ComparisonItem
            {
                IsSectionHeader = true,
                SectionTitle = categoryName,
                SectionSubtitle = GetSectionDescription(categoryName),
                SectionTag = GetSectionTag(categoryName),
                SectionCheckCount = items.Count
            });

            foreach (ComparisonItem item in items)
                target.Add(item);
        }

        private static string GetSectionDescription(string categoryName)
        {
            return categoryName switch
            {
                "System Information" => "SMBIOS system IDs",
                "Operating System" => "Windows install and machine IDs",
                "BIOS Information" => "Firmware details and security settings",
                "TPM Information" => "TPM status, certificate serial, and thumbprint",
                "Baseboard Information" => "Motherboard model, asset tag, and serial",
                "Processor Information" => "Processor details and reported IDs",
                "Chassis/Enclosure Information" => "Enclosure details and asset IDs",
                "Physical Memory (RAM)" => "Memory slots and module serials",
                "Disk Drive Information" => "Drive IDs from each query method",
                "Volume Serial Numbers" => "Volume IDs visible to Windows",
                "Network Information" => "Adapter settings and MAC addresses",
                "ARP Information" => "Current ARP entries; unchanged entries need attention",
                "Monitor Information" => "Monitor IDs read from EDID",
                "GPU Information" => "Graphics adapter IDs and driver details",
                "USB Peripherals" => "Current and disconnected USB records",
                _ => "Collected values"
            };
        }

        private static string GetSectionTag(string categoryName)
        {
            return categoryName switch
            {
                "System Information" or "Operating System" => "SYSTEM",
                "BIOS Information" or "TPM Information" => "TRUST",
                "Baseboard Information" or "Processor Information" or "Chassis/Enclosure Information" or "Physical Memory (RAM)" => "HARDWARE",
                "Disk Drive Information" or "Volume Serial Numbers" => "STORAGE",
                "Network Information" or "ARP Information" => "NETWORK",
                "Monitor Information" or "GPU Information" => "DISPLAY",
                "USB Peripherals" => "USB",
                _ => "CONTEXT"
            };
        }

        private static IEnumerable<string> GetNormalizedCategoryNames(IEnumerable<AuditCategory> data)
        {
            foreach (AuditCategory category in data)
            {
                if (Comparer.Equals(category.Name, "BIOS Information"))
                {
                    yield return "BIOS Information";
                    if (category.Items.Any(item => TpmLabels.Contains(item.Label ?? "")))
                        yield return "TPM Information";
                    continue;
                }

                yield return category.Name;
            }
        }

        private static IEnumerable<AuditItem> GetNormalizedItems(IEnumerable<AuditCategory> data, string categoryName)
        {
            foreach (AuditCategory category in data)
            {
                if (Comparer.Equals(categoryName, "TPM Information"))
                {
                    if (Comparer.Equals(category.Name, "TPM Information"))
                    {
                        foreach (AuditItem item in category.Items)
                            yield return NormalizeLegacyTpmItem(item);
                    }
                    else if (Comparer.Equals(category.Name, "BIOS Information"))
                    {
                        foreach (AuditItem item in category.Items.Where(item => TpmLabels.Contains(item.Label ?? "")))
                            yield return NormalizeLegacyTpmItem(item);
                    }
                }
                else if (Comparer.Equals(categoryName, "BIOS Information") && Comparer.Equals(category.Name, "BIOS Information"))
                {
                    foreach (AuditItem item in category.Items.Where(item => !TpmLabels.Contains(item.Label ?? "")))
                        yield return item;
                }
                else if (Comparer.Equals(category.Name, categoryName))
                {
                    foreach (AuditItem item in category.Items)
                        yield return item;
                }
            }
        }

        private static string GetComparisonValue(string categoryName, AuditItem? item)
        {
            if (item == null)
                return "";

            string value = item.Value ?? "";
            if (Comparer.Equals(categoryName, "ARP Information") &&
                !string.IsNullOrWhiteSpace(value) &&
                !string.IsNullOrWhiteSpace(item.TooltipText) &&
                item.TooltipText.StartsWith("IP:", StringComparison.OrdinalIgnoreCase))
            {
                return $"{item.TooltipText} · {value}";
            }

            return value;
        }

        private static AuditItem NormalizeLegacyTpmItem(AuditItem item)
        {
            if (!Comparer.Equals(item.Label, "Endorsement Key"))
                return item;

            return new AuditItem
            {
                Label = "Endorsement Key Thumbprint",
                Value = item.Value,
                TooltipText = item.TooltipText,
                IsSeparator = item.IsSeparator,
                IsPlaceholder = item.IsPlaceholder
            };
        }

        private static Dictionary<string, AuditItem> BuildItemMap(IEnumerable<AuditItem> items)
        {
            var result = new Dictionary<string, AuditItem>(Comparer);
            var occurrences = new Dictionary<string, int>(Comparer);

            foreach (AuditItem item in items)
            {
                string label = item.Label ?? "";
                if (item.IsSeparator || label.StartsWith("---", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(label))
                    continue;

                occurrences.TryGetValue(label, out int occurrence);
                occurrences[label] = occurrence + 1;
                result[$"{label}{OccurrenceSeparator}{occurrence}"] = item;
            }

            return result;
        }

        private static ComparisonItem AssessItem(
            string category,
            string label,
            string oldValue,
            string newValue,
            int occurrence,
            DiskContext? diskContext,
            TpmContext? tpmContext)
        {
            bool changed = !string.Equals(oldValue.Trim(), newValue.Trim(), StringComparison.OrdinalIgnoreCase);
            ComparisonExpectation expectation = GetExpectation(category, label);
            var item = new ComparisonItem
            {
                Category = category,
                Label = label,
                OldValue = string.IsNullOrWhiteSpace(oldValue) ? "—" : oldValue,
                NewValue = string.IsNullOrWhiteSpace(newValue) ? "—" : newValue,
                IsChanged = changed,
                Expectation = expectation,
                IsGroupHeader = Comparer.Equals(label, "DISK_STORAGE_MODEL") ||
                                (Comparer.Equals(category, "TPM Information") && Comparer.Equals(label, "TPM Status"))
            };

            if (Comparer.Equals(label, "DISK_STORAGE_MODEL"))
            {
                item.GroupTitle = $"Drive {occurrence + 1}";
                item.GroupSubtitle = "Drive model for the serial checks below";
            }
            else if (Comparer.Equals(category, "TPM Information") && Comparer.Equals(label, "TPM Status"))
            {
                item.GroupTitle = "Trusted Platform Module";
                item.GroupSubtitle = "Status and endorsement certificate";
            }

            bool oldMissing = string.IsNullOrWhiteSpace(oldValue);
            bool newMissing = string.IsNullOrWhiteSpace(newValue);
            bool oldUnavailable = IsUnavailableValue(oldValue);
            bool newUnavailable = IsUnavailableValue(newValue);
            bool oldGeneric = IsGenericValue(oldValue);
            bool newGeneric = IsGenericValue(newValue);
            bool isDiskIdentifier = Comparer.Equals(category, "Disk Drive Information") && DiskIdentifierLabels.Contains(label);

            // An unchanged ARP entry means the same network trace is still exposed. Removal, hiding, or
            // a changed entry is the desired privacy result for this spoofing-focused comparison.
            if (Comparer.Equals(category, "ARP Information"))
            {
                bool currentArpHidden = newMissing || newUnavailable ||
                                        newValue.Contains("No arp information", StringComparison.OrdinalIgnoreCase);
                bool arpChanged = changed || oldMissing || currentArpHidden;
                item.Outcome = arpChanged ? ComparisonOutcome.Pass : ComparisonOutcome.Attention;
                item.ResultTitle = currentArpHidden
                    ? "Removed or hidden"
                    : arpChanged
                        ? "ARP entry changed"
                        : "ARP entry unchanged";
                item.ResultDetail = currentArpHidden
                    ? "No longer readable. A hidden or removed ARP entry passes this check."
                    : arpChanged
                        ? "The IP or MAC no longer matches the baseline."
                        : "The same IP and MAC are still readable. Check this ARP entry.";
                return item;
            }

            // TPM state, descriptive context, and endorsement identifiers carry different meanings.
            // Ownership changes are state changes; the endorsement rows remain the identity verdicts.
            if (Comparer.Equals(category, "TPM Information"))
            {
                if (Comparer.Equals(label, "TPM Status"))
                {
                    if (tpmContext?.BaselineReadyAndOwned == true && tpmContext.CurrentLooksDisabled)
                    {
                        item.Outcome = ComparisonOutcome.Pass;
                        item.ResultTitle = "TPM disabled or hidden";
                        item.ResultDetail = "The owned TPM from the baseline is now disabled or unreadable. Check the endorsement rows for its IDs.";
                    }
                    else if (tpmContext?.CurrentIsUnowned == true)
                    {
                        item.Outcome = changed ? ComparisonOutcome.Info : ComparisonOutcome.Stable;
                        item.ResultTitle = changed ? "TPM now unowned" : "Stable · unowned";
                        item.ResultDetail = changed
                            ? "Ownership was cleared. The serial and thumbprint may still be readable, so check those rows."
                            : "The TPM is still unowned. Stable status does not pass the serial or thumbprint checks.";
                    }
                    else if (tpmContext?.CurrentLooksDisabled == true)
                    {
                        item.Outcome = changed ? ComparisonOutcome.Info : ComparisonOutcome.Stable;
                        item.ResultTitle = changed ? "TPM unavailable" : "Stable · unavailable";
                        item.ResultDetail = changed
                            ? "The TPM is now disabled or hidden. The baseline did not confirm a ready, owned TPM."
                            : "The TPM is still unavailable. The baseline cannot confirm an ID change.";
                    }
                    else
                    {
                        item.Outcome = changed ? ComparisonOutcome.Attention : ComparisonOutcome.Stable;
                        item.ResultTitle = changed ? "TPM state changed" : "Stable";
                        item.ResultDetail = changed
                            ? "The status changed. Check ownership, provisioning, firmware, and BIOS settings."
                            : "The status is unchanged. Stable status is context, not a spoofing pass.";
                    }
                    return item;
                }

                if (IsTpmContextField(label))
                {
                    bool unavailableWithStateChange = (newMissing || newUnavailable) &&
                                                      (tpmContext?.CurrentLooksDisabled == true || tpmContext?.CurrentIsUnowned == true);
                    item.Outcome = changed && !unavailableWithStateChange
                        ? ComparisonOutcome.Attention
                        : ComparisonOutcome.Info;
                    item.ResultTitle = unavailableWithStateChange
                        ? "Unavailable with TPM state"
                        : changed
                            ? "Unexpected context change"
                            : "Context unchanged";
                    item.ResultDetail = unavailableWithStateChange
                        ? "This field is unreadable with the current TPM status. Use the endorsement rows for the ID checks."
                        : changed
                            ? "The TPM manufacturer or specification changed. Ownership changes should not rewrite it."
                            : "The manufacturer or specification is unchanged. This is informational.";
                    return item;
                }

                if (IsTpmEndorsementIdentifier(label))
                {
                    if (oldMissing)
                    {
                        item.Outcome = ComparisonOutcome.Info;
                        item.ResultTitle = "New TPM check";
                        item.ResultDetail = "The old baseline did not store this field. Save a new baseline before checking it.";
                        return item;
                    }

                    if (newGeneric && !newUnavailable)
                    {
                        item.Outcome = ComparisonOutcome.Info;
                        item.ResultTitle = "Generic TPM identifier";
                        item.ResultDetail = "This is a shared placeholder, not a unique ID. It cannot prove an endorsement ID change.";
                        return item;
                    }

                    if (newMissing || newUnavailable)
                    {
                        if (!oldUnavailable && !oldGeneric)
                        {
                            item.Outcome = ComparisonOutcome.Pass;
                            item.ResultTitle = tpmContext?.CurrentIsUnowned == true
                                ? "Hidden while unowned"
                                : "TPM identity hidden";
                            item.ResultDetail = tpmContext?.CurrentIsUnowned == true
                                ? "The baseline ID is unreadable while the TPM is unowned. The visibility check passes; the key itself may be unchanged."
                                : "The baseline ID is no longer readable from this query.";
                        }
                        else
                        {
                            item.Outcome = ComparisonOutcome.Unavailable;
                            item.ResultTitle = "No readable identity";
                            item.ResultDetail = tpmContext?.CurrentIsUnowned == true
                                ? "Neither audit has a readable ID, and the TPM is unowned. No change can be confirmed."
                                : "Neither audit has a readable endorsement ID. There is nothing to compare.";
                        }
                        return item;
                    }

                    if (oldUnavailable || oldGeneric)
                    {
                        item.Outcome = ComparisonOutcome.Attention;
                        item.ResultTitle = "TPM identity exposed";
                        item.ResultDetail = "A unique endorsement ID is readable now. The baseline did not expose one.";
                        return item;
                    }

                    item.Outcome = changed ? ComparisonOutcome.Pass : ComparisonOutcome.Attention;
                    item.ResultTitle = changed ? "TPM identity changed" : "TPM identity unchanged";
                    item.ResultDetail = changed
                        ? "The endorsement ID differs from the baseline."
                        : tpmContext?.CurrentIsUnowned == true
                            ? "The TPM is unowned, but this ID still matches the baseline. Clearing ownership did not hide it."
                            : "The endorsement ID still matches the baseline. This check did not pass.";
                    return item;
                }
            }

            // A generic placeholder is non-unique, but it is not proof that a spoofer did anything.
            // Keep spoof-target serials neutral and explain why they cannot produce a pass verdict.
            if (newGeneric && expectation == ComparisonExpectation.ShouldChange &&
                (!isDiskIdentifier || !newUnavailable))
            {
                item.Outcome = ComparisonOutcome.Info;
                item.ResultTitle = "Generic identifier";
                item.ResultDetail = oldGeneric
                    ? "The value is a shared manufacturer placeholder. It was already generic, so it cannot prove a change."
                    : "The current value is a shared manufacturer placeholder. No unique serial is exposed, but the original ID may be unchanged.";
                return item;
            }

            if (!isDiskIdentifier && newGeneric)
            {
                item.Outcome = ComparisonOutcome.Info;
                item.ResultTitle = "Generic value";
                item.ResultDetail = "Shared placeholder. It is informational and has no pass or fail result.";
                return item;
            }

            if (!isDiskIdentifier && oldGeneric && !newGeneric && expectation == ComparisonExpectation.ShouldChange)
            {
                item.Outcome = ComparisonOutcome.Attention;
                item.ResultTitle = "Unique value exposed";
                item.ResultDetail = "The baseline had a shared placeholder. A unique ID is readable now.";
                return item;
            }

            if (oldMissing || newMissing)
            {
                if (newMissing && expectation == ComparisonExpectation.ShouldChange)
                {
                    item.Outcome = ComparisonOutcome.Pass;
                    item.ResultTitle = "Hidden from reads";
                    item.ResultDetail = "The baseline value is no longer readable from this query.";
                }
                else if (expectation == ComparisonExpectation.Informational)
                {
                    item.Outcome = ComparisonOutcome.Info;
                    item.ResultTitle = newMissing ? "Not present" : "Now present";
                    item.ResultDetail = "Context only. It does not affect the spoofing result.";
                }
                else
                {
                    item.Outcome = ComparisonOutcome.Attention;
                    item.ResultTitle = oldMissing ? "Identifier exposed" : "Missing now";
                    item.ResultDetail = oldMissing
                        ? "This value was absent from the baseline and is readable now."
                        : "A value expected to stay the same is now missing.";
                }
                return item;
            }

            if (oldUnavailable && newUnavailable)
            {
                item.Outcome = ComparisonOutcome.Unavailable;
                item.ResultTitle = "Not exposed";
                item.ResultDetail = BuildUnavailableDetail(label, diskContext);
                return item;
            }

            if (!oldUnavailable && newUnavailable)
            {
                if (diskContext?.WasLegacyCopiedValue(label, oldValue) == true)
                {
                    item.Outcome = ComparisonOutcome.Unavailable;
                    item.ResultTitle = "Legacy baseline";
                    item.ResultDetail = "The old app copied STORAGE_QUERY_PROPERTY here. Save a new baseline for this query method.";
                }
                else if (expectation == ComparisonExpectation.ShouldChange)
                {
                    item.Outcome = ComparisonOutcome.Pass;
                    item.ResultTitle = "Hidden from reads";
                    item.ResultDetail = "The query now returns zero or unavailable. The ID is hidden from this method; the hardware serial may be unchanged.";
                }
                else
                {
                    item.Outcome = ComparisonOutcome.Attention;
                    item.ResultTitle = "Unavailable now";
                    item.ResultDetail = "The query is blocked or unavailable now. The ID is hidden, but its stored value may be unchanged.";
                }
                return item;
            }

            if (oldUnavailable && !newUnavailable)
            {
                item.Outcome = expectation == ComparisonExpectation.ShouldChange
                    ? ComparisonOutcome.Attention
                    : ComparisonOutcome.Info;
                item.ResultTitle = expectation == ComparisonExpectation.ShouldChange ? "Identifier exposed" : "Now readable";
                item.ResultDetail = expectation == ComparisonExpectation.ShouldChange
                    ? "A unique ID is readable now. It was unavailable in the baseline."
                    : "The value is readable now. It was unavailable in the baseline, so this is informational.";
                return item;
            }

            switch (expectation)
            {
                case ComparisonExpectation.ShouldChange:
                    item.Outcome = changed ? ComparisonOutcome.Pass : ComparisonOutcome.Attention;
                    item.ResultTitle = changed ? "Changed as expected" : "Still unchanged";
                    item.ResultDetail = changed
                        ? "The ID differs from the baseline."
                        : "The ID still matches the baseline. This check did not pass.";
                    break;

                case ComparisonExpectation.ShouldStayStable:
                    item.Outcome = changed ? ComparisonOutcome.Attention : ComparisonOutcome.Stable;
                    item.ResultTitle = changed ? "Unexpected change" : "Stable";
                    item.ResultDetail = BuildStableDetail(category, label, changed);
                    break;

                default:
                    item.Outcome = ComparisonOutcome.Info;
                    item.ResultTitle = changed ? "Changed" : "No change";
                    item.ResultDetail = changed
                        ? "Context value changed. It does not affect the spoofing result."
                        : "Context value unchanged.";
                    break;
            }

            return item;
        }

        private static ComparisonExpectation GetExpectation(string category, string label)
        {
            if (Comparer.Equals(category, "TPM Information"))
                return IsTpmEndorsementIdentifier(label)
                    ? ComparisonExpectation.ShouldChange
                    : Comparer.Equals(label, "TPM Status")
                        ? ComparisonExpectation.ShouldStayStable
                        : ComparisonExpectation.Informational;

            if (Comparer.Equals(category, "Disk Drive Information"))
                return Comparer.Equals(label, "DISK_STORAGE_MODEL")
                    ? ComparisonExpectation.ShouldStayStable
                    : DiskIdentifierLabels.Contains(label)
                        ? ComparisonExpectation.ShouldChange
                        : ComparisonExpectation.Informational;

            if (Comparer.Equals(category, "Operating System"))
            {
                if (Comparer.Equals(label, "Machine GUID") || Comparer.Equals(label, "Product ID"))
                    return ComparisonExpectation.ShouldChange;
                return Comparer.Equals(label, "Last Boot")
                    ? ComparisonExpectation.Informational
                    : ComparisonExpectation.ShouldStayStable;
            }

            if (Comparer.Equals(category, "System Information"))
                return Comparer.Equals(label, "System Serial") || Comparer.Equals(label, "System UUID")
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "BIOS Information"))
                return Comparer.Equals(label, "BIOS Serial")
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "Baseboard Information"))
                return Comparer.Equals(label, "Serial Number") || Comparer.Equals(label, "Asset Number")
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "Processor Information"))
                return Comparer.Equals(label, "Serial Number") || Comparer.Equals(label, "Asset Number")
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "Chassis/Enclosure Information"))
                return Comparer.Equals(label, "Serial Number") || Comparer.Equals(label, "Asset Number")
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "Physical Memory (RAM)"))
                return Comparer.Equals(label, "Serial Number")
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "Volume Serial Numbers"))
                return ComparisonExpectation.ShouldChange;

            if (Comparer.Equals(category, "Network Information"))
                return label.StartsWith("MAC [", StringComparison.OrdinalIgnoreCase)
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.Informational;

            if (Comparer.Equals(category, "ARP Information"))
                return ComparisonExpectation.Informational;

            if (Comparer.Equals(category, "Monitor Information"))
                return label.Contains("Serial", StringComparison.OrdinalIgnoreCase)
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "GPU Information"))
                return Comparer.Equals(label, "GUID Serial")
                    ? ComparisonExpectation.ShouldChange
                    : ComparisonExpectation.ShouldStayStable;

            if (Comparer.Equals(category, "USB Peripherals"))
                return Comparer.Equals(label, "Status")
                    ? ComparisonExpectation.Informational
                    : ComparisonExpectation.ShouldChange;

            return ComparisonExpectation.Informational;
        }

        private static string BuildStableDetail(string category, string label, bool changed)
        {
            if (Comparer.Equals(label, "DISK_STORAGE_MODEL"))
            {
                return changed
                    ? "The drive model changed. Check the drive or controller setup before using the serial results below."
                    : "The drive model matches. The serial rows below are the spoofing checks.";
            }

            if (Comparer.Equals(category, "TPM Information"))
            {
                if (changed && IsTpmEndorsementIdentifier(label))
                    return "The endorsement ID changed. Possible causes include a TPM clear, firmware reset, new certificate, or different TPM.";

                return changed
                    ? "TPM state changed. Check for a clear, firmware update, or ownership change."
                    : "TPM state is unchanged.";
            }

            return changed
                ? "This value was expected to stay the same. Check the hardware or system change."
                : "Unchanged, as expected.";
        }

        private static string BuildUnavailableDetail(string label, DiskContext? diskContext)
        {
            if (diskContext != null && diskContext.IsRaid)
            {
                string model = string.IsNullOrWhiteSpace(diskContext.Model) ? "This drive" : diskContext.Model;
                if (Comparer.Equals(label, "SMART_RCV_DRIVE_DATA") || Comparer.Equals(label, "ATA_PASS_THROUGH"))
                {
                    return $"{model} uses a RAID/SCSI layer. ATA and SMART pass-through can return zeros here. This is not a failed spoof.";
                }

                if (Comparer.Equals(label, "STORAGE_QUERY_WWN"))
                {
                    return $"{model}'s RAID driver does not provide a VPD WWN. Zeros are normal here, so this method cannot verify a change.";
                }

                if (Comparer.Equals(label, "SCSI_PASS_THROUGH"))
                {
                    return $"{model}'s RAID driver does not provide the SCSI unit-serial page. Zeros are normal here and have no verdict.";
                }
            }

            return "No usable value was returned. Matching zeros or unknown values cannot verify a change.";
        }

        private static bool IsUnavailableValue(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return true;

            string trimmed = value.Trim();
            if (IsZeroLike(trimmed))
                return true;

            return Comparer.Equals(trimmed, "Unknown") ||
                   Comparer.Equals(trimmed, "Unavailable") ||
                   Comparer.Equals(trimmed, "Default string") ||
                   Comparer.Equals(trimmed, "Requires Admin") ||
                   trimmed.StartsWith("Error accessing", StringComparison.OrdinalIgnoreCase) ||
                   trimmed.StartsWith("No ", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsGenericValue(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            string trimmed = value.Trim();
            if (IsZeroLike(trimmed))
                return true;

            string normalized = trimmed.Replace(".", "", StringComparison.Ordinal).Trim();
            return Comparer.Equals(trimmed, "Unknown") ||
                   Comparer.Equals(trimmed, "Unavailable") ||
                   Comparer.Equals(trimmed, "Default string") ||
                   Comparer.Equals(trimmed, "System Serial Number") ||
                   Comparer.Equals(trimmed, "System Product Name") ||
                   Comparer.Equals(trimmed, "System Version") ||
                   Comparer.Equals(trimmed, "Base Board Serial Number") ||
                   Comparer.Equals(trimmed, "Chassis Serial Number") ||
                   Comparer.Equals(trimmed, "Not Specified") ||
                   Comparer.Equals(trimmed, "Not Applicable") ||
                   Comparer.Equals(trimmed, "Not Available") ||
                   Comparer.Equals(trimmed, "No Asset Tag") ||
                   Comparer.Equals(trimmed, "Asset Tag") ||
                   Comparer.Equals(trimmed, "OEM") ||
                   Comparer.Equals(trimmed, "None") ||
                   Comparer.Equals(trimmed, "N/A") ||
                   Comparer.Equals(trimmed, "123456789") ||
                   Comparer.Equals(trimmed, "0123456789") ||
                   normalized.StartsWith("To be filled by OEM", StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith("To be filled by O E M", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsTpmEndorsementIdentifier(string label)
        {
            return Comparer.Equals(label, "Endorsement Key") ||
                   Comparer.Equals(label, "Endorsement Key Serial Number") ||
                   Comparer.Equals(label, "Endorsement Key Thumbprint");
        }

        private static bool IsTpmContextField(string label)
        {
            return Comparer.Equals(label, "Manufacturer ID") ||
                   Comparer.Equals(label, "Manufacturer Version") ||
                   Comparer.Equals(label, "Spec Version");
        }

        private static bool IsZeroLike(string value)
        {
            string compact = new string(value.Where(char.IsLetterOrDigit).ToArray());
            return compact.Length >= 4 && compact.All(character => character == '0');
        }

        private static bool IsImportant(string category, string label)
        {
            if (Comparer.Equals(category, "Disk Drive Information") ||
                Comparer.Equals(category, "ARP Information") ||
                Comparer.Equals(category, "USB Peripherals") ||
                Comparer.Equals(category, "TPM Information"))
            {
                return true;
            }

            if (Comparer.Equals(category, "System Information"))
                return Comparer.Equals(label, "System UUID");

            if (Comparer.Equals(category, "Baseboard Information") || Comparer.Equals(category, "Physical Memory (RAM)"))
                return Comparer.Equals(label, "Serial Number");

            if (Comparer.Equals(category, "Network Information"))
                return Comparer.Equals(label, "MAC [Kernel]") || Comparer.Equals(label, "MAC [Cache]");

            if (Comparer.Equals(category, "Monitor Information"))
                return Comparer.Equals(label, "Monitor Serial");

            return Comparer.Equals(category, "GPU Information") && Comparer.Equals(label, "GUID Serial");
        }

        private static DiskContext BuildDiskContext(
            IReadOnlyDictionary<string, AuditItem> oldItems,
            IReadOnlyDictionary<string, AuditItem> newItems,
            int occurrence)
        {
            string oldModel = GetMappedValue(oldItems, "DISK_STORAGE_MODEL", occurrence);
            string newModel = GetMappedValue(newItems, "DISK_STORAGE_MODEL", occurrence);
            return new DiskContext
            {
                Model = string.IsNullOrWhiteSpace(newModel) ? oldModel : newModel,
                OldPropertySerial = GetMappedValue(oldItems, "STORAGE_QUERY_PROPERTY", occurrence)
            };
        }

        private static TpmContext BuildTpmContext(
            IReadOnlyDictionary<string, AuditItem> oldItems,
            IReadOnlyDictionary<string, AuditItem> newItems)
        {
            return new TpmContext
            {
                OldStatus = GetMappedValue(oldItems, "TPM Status", 0),
                NewStatus = GetMappedValue(newItems, "TPM Status", 0)
            };
        }

        private static string GetMappedValue(IReadOnlyDictionary<string, AuditItem> items, string label, int occurrence)
        {
            return items.TryGetValue($"{label}{OccurrenceSeparator}{occurrence}", out AuditItem? item)
                ? item.Value ?? ""
                : "";
        }

        private static int GetOccurrence(string key)
        {
            int separatorIndex = key.LastIndexOf(OccurrenceSeparator);
            return separatorIndex >= 0 && int.TryParse(key[(separatorIndex + 1)..], out int occurrence)
                ? occurrence
                : 0;
        }

        private sealed class DiskContext
        {
            public string Model { get; init; } = "";
            public string OldPropertySerial { get; init; } = "";
            public bool IsRaid => Model.Contains("RAID", StringComparison.OrdinalIgnoreCase);

            public bool WasLegacyCopiedValue(string label, string oldValue)
            {
                return (Comparer.Equals(label, "SMART_RCV_DRIVE_DATA") ||
                        Comparer.Equals(label, "SCSI_PASS_THROUGH") ||
                        Comparer.Equals(label, "ATA_PASS_THROUGH") ||
                        Comparer.Equals(label, "STORAGE_QUERY_WWN")) &&
                       !string.IsNullOrWhiteSpace(OldPropertySerial) &&
                       Comparer.Equals(oldValue.Trim(), OldPropertySerial.Trim());
            }
        }

        private sealed class TpmContext
        {
            public string OldStatus { get; init; } = "";
            public string NewStatus { get; init; } = "";
            public bool BaselineReadyAndOwned => OldStatus.Contains("Ready & Owned", StringComparison.OrdinalIgnoreCase);
            public bool CurrentIsUnowned => NewStatus.Contains("Unowned", StringComparison.OrdinalIgnoreCase) ||
                                            NewStatus.Contains("Not Ready", StringComparison.OrdinalIgnoreCase);
            public bool CurrentLooksDisabled =>
                NewStatus.Contains("Not Present", StringComparison.OrdinalIgnoreCase) ||
                NewStatus.Contains("Disabled", StringComparison.OrdinalIgnoreCase) ||
                NewStatus.Contains("Inactive", StringComparison.OrdinalIgnoreCase) ||
                NewStatus.Contains("Unavailable", StringComparison.OrdinalIgnoreCase);
        }

        private void ImportantTab_Checked(object sender, RoutedEventArgs e)
        {
            ShowScope(_importantComparisonItems, "Key spoofing checks");
        }

        private void AllTab_Checked(object sender, RoutedEventArgs e)
        {
            ShowScope(_allComparisonItems, "Every collected value");
        }

        private void ShowScope(ObservableCollection<ComparisonItem> items, string description)
        {
            ComparisonItems = items;
            IEnumerable<ComparisonItem> verdictItems = items.Where(item => !item.IsSectionHeader);
            PassedCount = verdictItems.Count(item => item.IsPass);
            StableCount = verdictItems.Count(item => item.IsStable);
            AttentionCount = verdictItems.Count(item => item.NeedsAttention);
            UnavailableCount = verdictItems.Count(item => item.IsUnavailable);
            InformationalCount = verdictItems.Count(item => item.IsInformational);
            SummaryText = $"{PassedCount} passed  ·  {StableCount} stable  ·  {AttentionCount} attention  ·  {UnavailableCount} unavailable  ·  {InformationalCount} info";
            ActiveScopeDescription = description;
            OnPropertyChanged(nameof(PassedCount));
            OnPropertyChanged(nameof(StableCount));
            OnPropertyChanged(nameof(AttentionCount));
            OnPropertyChanged(nameof(UnavailableCount));
            OnPropertyChanged(nameof(InformationalCount));

            if (DataScrollViewer != null)
            {
                DataScrollViewer.ScrollToTop();
                var ease = new QuinticEase { EasingMode = EasingMode.EaseOut };
                DataScrollViewer.BeginAnimation(OpacityProperty, new DoubleAnimation(0.3, 1, TimeSpan.FromMilliseconds(240))
                {
                    EasingFunction = ease
                }, HandoffBehavior.SnapshotAndReplace);

                if (DataScrollViewer.RenderTransform is TranslateTransform translate)
                {
                    translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(5, 0, TimeSpan.FromMilliseconds(300))
                    {
                        EasingFunction = ease
                    }, HandoffBehavior.SnapshotAndReplace);
                }
            }
        }

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(230))
            {
                EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseIn }
            };
            fadeOut.Completed += (s, a) => Close();
            BeginAnimation(OpacityProperty, fadeOut);
        }

        private void DragWindow_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                DragMove();
        }
    }
}
