using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Security.Principal;
using System.Diagnostics;
using SystemHardwareAudit.Models;

namespace SystemHardwareAudit
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public ObservableCollection<AuditCategory> Categories { get; set; } = new ObservableCollection<AuditCategory>();

        private AuditCategory _selectedCategory;
        public AuditCategory SelectedCategory
        {
            get => _selectedCategory;
            set
            {
                _selectedCategory = value;
                OnPropertyChanged(nameof(SelectedCategory));
                OnPropertyChanged(nameof(SelectedCategoryDescription));
                OnPropertyChanged(nameof(SelectedCategoryItemCount));
                OnPropertyChanged(nameof(SelectedCategoryContextLabel));

                if (IsLoaded)
                    Dispatcher.BeginInvoke(AnimateCategoryTransition);
            }
        }

        public string SelectedCategoryDescription => GetCategoryDescription(SelectedCategory?.Name);
        public int SelectedCategoryItemCount => SelectedCategory?.Items?.Count(item => !item.IsSeparator) ?? 0;
        public string SelectedCategoryContextLabel => GetCategoryContextLabel(SelectedCategory?.Name);

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public MainWindow()
        {
            bool isAdmin = false;
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { }

            if (!isAdmin)
            {
                try
                {
                    ProcessStartInfo startInfo = new ProcessStartInfo(Environment.ProcessPath)
                    {
                        UseShellExecute = true,
                        Verb = "runas"
                    };
                    Process.Start(startInfo);
                    Environment.Exit(0);
                }
                catch (Win32Exception)
                {
                    //  User declined UAC prompt. Continue as standard user.
                }
                catch { }
            }

            InitializeComponent();
            DataContext = this;
        }

        private static string GetCategoryDescription(string? categoryName)
        {
            return categoryName switch
            {
                "System Information" => "SMBIOS system details and IDs.",
                "Operating System" => "Windows version, install details, and machine IDs.",
                "BIOS Information" => "Firmware details and security settings.",
                "TPM Information" => "TPM status, firmware, certificate serial, and thumbprint.",
                "Baseboard Information" => "Motherboard model, revision, asset tag, and serial.",
                "Processor Information" => "Processor model, topology, and reported IDs.",
                "Physical Memory (RAM)" => "Memory modules, slots, and serials.",
                "Disk Drive Information" => "Drive IDs read through each supported query path.",
                "Volume Serial Numbers" => "Volume IDs visible to Windows.",
                "Network Information" => "Adapter settings, kernel MAC, and cached MAC.",
                "ARP Information" => "Entries currently visible in the ARP table.",
                "Monitor Information" => "Monitor IDs decoded from EDID.",
                "GPU Information" => "Graphics adapter IDs and driver details.",
                "USB Peripherals" => "Current and disconnected USB device records.",
                _ => "Collected hardware and system values."
            };
        }

        private static string GetCategoryContextLabel(string? categoryName)
        {
            return categoryName switch
            {
                "System Information" or "Operating System" => "SYSTEM IDENTITY",
                "BIOS Information" or "TPM Information" => "FIRMWARE & TRUST",
                "Baseboard Information" or "Processor Information" or "Physical Memory (RAM)" => "CORE HARDWARE",
                "Disk Drive Information" or "Volume Serial Numbers" => "STORAGE",
                "Network Information" or "ARP Information" => "NETWORK",
                "Monitor Information" or "GPU Information" => "DISPLAY",
                "USB Peripherals" => "PERIPHERALS",
                _ => "AUDIT CATEGORY"
            };
        }

        private void AnimateCategoryTransition()
        {
            if (DetailContent == null)
                return;

            DetailScrollViewer?.ScrollToTop();
            var ease = new QuinticEase { EasingMode = EasingMode.EaseOut };
            DetailContent.BeginAnimation(OpacityProperty, new DoubleAnimation(0.35, 1, TimeSpan.FromMilliseconds(260))
            {
                EasingFunction = ease
            }, HandoffBehavior.SnapshotAndReplace);

            if (DetailContent.RenderTransform is TranslateTransform translate)
            {
                translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(5, 0, TimeSpan.FromMilliseconds(320))
                {
                    EasingFunction = ease
                }, HandoffBehavior.SnapshotAndReplace);
            }
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                var data = await Task.Run(() => SystemInfoGatherer.GetSystemAudit());
                
                foreach (var cat in data)
                {
                    Categories.Add(cat);
                }

                if (Categories.Count > 0)
                {
                    SelectedCategory = Categories[0];
                }

                var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(320))
                {
                    EasingFunction = new QuinticEase { EasingMode = EasingMode.EaseInOut }
                };
                fadeOut.Completed += (s, ev) => { LoadingScreen.Visibility = Visibility.Collapsed; };
                LoadingScreen.BeginAnimation(UIElement.OpacityProperty, fadeOut);
            }
            catch (Exception ex)
            {
                ShowToast("Initialization Error", ex.Message, isError: true);
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            var anim = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(240))
            {
                EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseIn }
            };
            anim.Completed += (s, ev) => Application.Current.Shutdown();
            this.BeginAnimation(UIElement.OpacityProperty, anim);
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            DragMove();
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string path = Path.Combine(desktop, "Master_System_Hardware_Audit.txt");
                
                using (StreamWriter sw = new StreamWriter(path))
                {
                    sw.WriteLine("==========================================");
                    sw.WriteLine("       MASTER SPOOFED? AUDIT       ");
                    sw.WriteLine("==========================================");
                    sw.WriteLine($"Generated: {DateTime.Now}");
                    sw.WriteLine();

                    foreach (var cat in Categories)
                    {
                        sw.WriteLine($"[{cat.Name.ToUpper()}]");
                        foreach (var item in cat.Items)
                        {
                            sw.WriteLine($"{item.Label,-25}: {item.Value}");
                        }
                        sw.WriteLine();
                    }
                }
                ShowToast("Export saved", "The audit is on your Desktop.");
            }
            catch (Exception ex)
            {
                ShowToast("Export failed", ex.Message, isError: true);
            }
        }

        private void SaveBaseline_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string folder = Path.Combine(appData, "SystemHardwareAudit");
                Directory.CreateDirectory(folder);
                string path = Path.Combine(folder, "baseline.json");

                string json = JsonSerializer.Serialize(Categories);
                File.WriteAllText(path, json);
                ShowToast("Baseline saved", "Run the spoofer, then compare again.");
            }
            catch (Exception ex)
            {
                ShowToast("Baseline failed", ex.Message, isError: true);
            }
        }

        private async void CompareButton_Click(object sender, RoutedEventArgs e)
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string path = Path.Combine(appData, "SystemHardwareAudit", "baseline.json");

            if (!File.Exists(path))
            {
                ShowToast("No baseline", "Save a baseline before comparing.");
                return;
            }

            try
            {
                LoadingScreen.Visibility = Visibility.Visible;
                LoadingScreen.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220))
                {
                    EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseOut }
                }, HandoffBehavior.SnapshotAndReplace);

                string json = File.ReadAllText(path);
                var oldData = JsonSerializer.Deserialize<ObservableCollection<AuditCategory>>(json);
                
                // Re-gather current hardware state
                var currentDataList = await Task.Run(() => SystemInfoGatherer.GetSystemAudit());
                var currentData = new ObservableCollection<AuditCategory>(currentDataList);
                
                // Update the main UI list as well
                Categories.Clear();
                foreach (var cat in currentDataList) Categories.Add(cat);
                if (Categories.Count > 0 && SelectedCategory == null) SelectedCategory = Categories[0];

                var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(260))
                {
                    EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseInOut }
                };
                fadeOut.Completed += (s, ev) => { LoadingScreen.Visibility = Visibility.Collapsed; };
                LoadingScreen.BeginAnimation(UIElement.OpacityProperty, fadeOut);

                ComparisonWindow cmpWin = new ComparisonWindow(oldData, currentData);
                cmpWin.Owner = this;
                cmpWin.ShowDialog();
            }
            catch (Exception ex)
            {
                ShowToast("Compare failed", ex.Message, isError: true);
            }
        }

        // ── Ghost Device Cleanup ──────────────────────────────
        private void GhostCleanup_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedCategory == null || SelectedCategory.Name != "USB Peripherals") return;

            var ghostDevices = SelectedCategory.Items.Where(i => i.Label.Contains("[GHOST]")).ToList();
            if (ghostDevices.Count == 0)
            {
                ShowToast("No ghost devices", "No disconnected USB records were found.");
                return;
            }

            try
            {
                string scriptPath = Path.Combine(Path.GetTempPath(), "GhostCleanup.ps1");
                var lines = new List<string> { "$ErrorActionPreference = 'SilentlyContinue'" };
                
                var instanceIds = new List<string>();
                foreach (var ghost in ghostDevices)
                {
                    string instanceId = ghost.TooltipText;
                    if (instanceId.StartsWith("USB\\"))
                    {
                        instanceIds.Add($"\"{instanceId}\"");
                    }
                }
                
                lines.Add("$ids = @(" + string.Join(", ", instanceIds) + ")");
                lines.Add("foreach ($id in $ids) {");
                lines.Add("    $removed = $false");
                lines.Add("    try { Get-PnpDevice -InstanceId $id -ErrorAction Stop | Remove-PnpDevice -Confirm:$false -ErrorAction Stop; $removed = $true } catch {}");
                lines.Add("    if (-not $removed) {");
                lines.Add("        try { & pnputil.exe /remove-device \"$id\" 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $removed = $true } } catch {}");
                lines.Add("    }");
                lines.Add("    if (-not $removed) {");
                lines.Add("        try { & reg.exe delete \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\$id\" /f 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $removed = $true } } catch {}");
                lines.Add("    }");
                lines.Add("}");

                File.WriteAllLines(scriptPath, lines);

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{scriptPath}\"",
                    UseShellExecute = true,
                    Verb = "runas", // Triggers UAC prompt
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var proc = Process.Start(psi);
                proc.WaitForExit();

                ShowToast("Cleanup finished", $"Requested removal of {ghostDevices.Count} device record(s). Refreshing the list.");
                
                // Refresh list automatically
                var updatedUsb = SystemInfoGatherer.GetSystemAudit().FirstOrDefault(c => c.Name == "USB Peripherals");
                if (updatedUsb != null)
                {
                    int index = Categories.IndexOf(SelectedCategory);
                    Categories[index] = updatedUsb;
                    SelectedCategory = Categories[index];
                }
            }
            catch (Exception)
            {
                ShowToast("Cleanup failed", "Approve the administrator prompt to remove these records.", isError: true);
            }
        }

        // ── Full-Screen Modal Notification ──────────────────────────────
        private async void ShowToast(string title, string subtitle, bool isError = false)
        {
            ToastTitle.Text = title;
            ToastSubtitle.Text = subtitle;

            // Set icon and colors based on type
            if (isError)
            {
                ToastIcon.Text = "✕";
                ToastIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF6B6B"));
                ToastTitle.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF6B6B"));
            }
            else
            {
                ToastIcon.Text = "✓";
                ToastIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#5856D6"));
                ToastTitle.Foreground = new SolidColorBrush(Colors.White);
            }

            // Reset state
            ToastDismissBtn.IsEnabled = false;
            ToastDismissBtn.Opacity = 0.3;
            ToastDismissBtn.Content = "Wait (3)";
            ToastProgressBar.Width = 0;

            // Show scrim
            ToastScrim.Visibility = Visibility.Visible;
            ToastScrim.UpdateLayout(); // Force layout so ActualWidth is correct

            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(240))
            {
                EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseOut }
            };
            ToastScrim.BeginAnimation(UIElement.OpacityProperty, fadeIn);

            if (ToastCard.RenderTransform is ScaleTransform toastScale)
            {
                toastScale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(0.99, 1, TimeSpan.FromMilliseconds(300))
                {
                    EasingFunction = new QuinticEase { EasingMode = EasingMode.EaseOut }
                }, HandoffBehavior.SnapshotAndReplace);
                toastScale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(0.99, 1, TimeSpan.FromMilliseconds(300))
                {
                    EasingFunction = new QuinticEase { EasingMode = EasingMode.EaseOut }
                }, HandoffBehavior.SnapshotAndReplace);
            }

            // Animate progress bar over 3 seconds
            double targetWidth = ToastProgressTrack.ActualWidth;
            if (targetWidth <= 0) targetWidth = 300; // safe fallback

            var progressAnim = new DoubleAnimation(0, targetWidth, TimeSpan.FromSeconds(3));
            ToastProgressBar.BeginAnimation(FrameworkElement.WidthProperty, progressAnim);

            // Countdown labels
            for (int i = 3; i >= 1; i--)
            {
                ToastDismissBtn.Content = $"Wait ({i})";
                await Task.Delay(1000);
            }

            // Enable dismiss
            ToastDismissBtn.Content = "Dismiss";
            ToastDismissBtn.IsEnabled = true;
            var btnFadeIn = new DoubleAnimation(0.3, 1, TimeSpan.FromMilliseconds(220))
            {
                EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseOut }
            };
            ToastDismissBtn.BeginAnimation(UIElement.OpacityProperty, btnFadeIn);
        }

        private void ToastDismiss_Click(object sender, RoutedEventArgs e)
        {
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(220))
            {
                EasingFunction = new QuarticEase { EasingMode = EasingMode.EaseIn }
            };
            if (ToastCard.RenderTransform is ScaleTransform toastScale)
            {
                var settle = new QuarticEase { EasingMode = EasingMode.EaseIn };
                toastScale.BeginAnimation(ScaleTransform.ScaleXProperty, new DoubleAnimation(1, 0.995, TimeSpan.FromMilliseconds(220)) { EasingFunction = settle });
                toastScale.BeginAnimation(ScaleTransform.ScaleYProperty, new DoubleAnimation(1, 0.995, TimeSpan.FromMilliseconds(220)) { EasingFunction = settle });
            }
            fadeOut.Completed += (s, ev) =>
            {
                ToastScrim.Visibility = Visibility.Collapsed;
            };
            ToastScrim.BeginAnimation(UIElement.OpacityProperty, fadeOut);
        }
    }
}
