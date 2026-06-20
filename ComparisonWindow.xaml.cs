using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Animation;
using SystemHardwareAudit.Models;

namespace SystemHardwareAudit
{
    public class ComparisonItem
    {
        public string Category { get; set; } = "";
        public string Label { get; set; } = "";
        public string OldValue { get; set; } = "";
        public string NewValue { get; set; } = "";
        public bool IsChanged { get; set; }
        public bool IsSeparator { get; set; }
    }

    public partial class ComparisonWindow : Window
    {
        public ObservableCollection<ComparisonItem> ComparisonItems { get; set; } = new ObservableCollection<ComparisonItem>();
        
        public int TotalItems { get; set; }
        public int ChangedItems { get; set; }
        public string SummaryText => ChangedItems == 0 
            ? "No changes detected — hardware matches baseline." 
            : $"{ChangedItems} of {TotalItems} values changed since baseline.";

        public ComparisonWindow(ObservableCollection<AuditCategory> oldData, ObservableCollection<AuditCategory> currentData)
        {
            InitializeComponent();
            DataContext = this;
            BuildComparison(oldData, currentData);
        }

        private void BuildComparison(ObservableCollection<AuditCategory> oldData, ObservableCollection<AuditCategory> currentData)
        {
            int total = 0;
            int changed = 0;

            // Build a combined set of all category names from both old and new
            var allCategoryNames = oldData.Select(c => c.Name)
                .Union(currentData.Select(c => c.Name))
                .ToList();

            foreach (var catName in allCategoryNames)
            {
                var oldCat = oldData.FirstOrDefault(c => c.Name == catName);
                var newCat = currentData.FirstOrDefault(c => c.Name == catName);

                var oldItems = oldCat?.Items ?? new List<AuditItem>();
                var newItems = newCat?.Items ?? new List<AuditItem>();

                int maxCount = Math.Max(oldItems.Count, newItems.Count);

                for (int i = 0; i < maxCount; i++)
                {
                    var oldItem = i < oldItems.Count ? oldItems[i] : null;
                    var newItem = i < newItems.Count ? newItems[i] : null;

                    string label = oldItem?.Label ?? newItem?.Label ?? "";
                    string oldVal = oldItem?.Value ?? "";
                    string newVal = newItem?.Value ?? "";

                    // Skip separator rows
                    if (label.StartsWith("---") || string.IsNullOrWhiteSpace(label))
                    {
                        ComparisonItems.Add(new ComparisonItem { IsSeparator = true });
                        continue;
                    }

                    // Skip empty/interface header rows ,
                    if (string.IsNullOrWhiteSpace(oldVal) && string.IsNullOrWhiteSpace(newVal))
                        continue;

                    bool isChanged = !string.Equals(oldVal.Trim(), newVal.Trim(), StringComparison.OrdinalIgnoreCase);
                    total++;
                    if (isChanged) changed++;

                    ComparisonItems.Add(new ComparisonItem
                    {
                        Category = catName,
                        Label = label,
                        OldValue = oldVal,
                        NewValue = newVal,
                        IsChanged = isChanged
                    });
                }
            }

            TotalItems = total;
            ChangedItems = changed;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(200));
            fadeOut.Completed += (s, a) => this.Close();
            this.BeginAnimation(OpacityProperty, fadeOut);
        }

        private void DragWindow_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                this.DragMove();
        }
    }
}
