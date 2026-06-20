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
            }
        }

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
                    // User declined UAC prompt. Continue as standard user.
                }
                catch { }
            }

            InitializeComponent();
            DataContext = this;
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

                // Fade out loading screen
                var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromSeconds(0.5));
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
            var anim = new DoubleAnimation(1, 0, TimeSpan.FromSeconds(0.2));
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
                ShowToast("Export Complete", "Hardware audit saved to your Desktop.");
            }
            catch (Exception ex)
            {
                ShowToast("Export Failed", ex.Message, isError: true);
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
                ShowToast("Baseline Captured", "You may now spoof your hardware. Once complete, press Compare to verify changes.");
            }
            catch (Exception ex)
            {
                ShowToast("Baseline Failed", ex.Message, isError: true);
            }
        }

        private async void CompareButton_Click(object sender, RoutedEventArgs e)
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string path = Path.Combine(appData, "SystemHardwareAudit", "baseline.json");

            if (!File.Exists(path))
            {
                ShowToast("No Baseline Found", "Save a baseline first to capture your pre-spoof hardware state.");
                return;
            }

            try
            {
                // Show loading screen
                LoadingScreen.Visibility = Visibility.Visible;
                LoadingScreen.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromSeconds(0.2)));

                string json = File.ReadAllText(path);
                var oldData = JsonSerializer.Deserialize<ObservableCollection<AuditCategory>>(json);
                
                // Re-gather current hardware state
                var currentDataList = await Task.Run(() => SystemInfoGatherer.GetSystemAudit());
                var currentData = new ObservableCollection<AuditCategory>(currentDataList);
                
                // Update the main UI list as well
                Categories.Clear();
                foreach (var cat in currentDataList) Categories.Add(cat);
                if (Categories.Count > 0 && SelectedCategory == null) SelectedCategory = Categories[0];

                // Hide loading screen
                var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromSeconds(0.2));
                fadeOut.Completed += (s, ev) => { LoadingScreen.Visibility = Visibility.Collapsed; };
                LoadingScreen.BeginAnimation(UIElement.OpacityProperty, fadeOut);

                ComparisonWindow cmpWin = new ComparisonWindow(oldData, currentData);
                cmpWin.Owner = this;
                cmpWin.ShowDialog();
            }
            catch (Exception ex)
            {
                ShowToast("Comparison Error", ex.Message, isError: true);
            }
        }

        // ── Ghost Device Cleanup ──────────────────────────────
        private void GhostCleanup_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedCategory == null || SelectedCategory.Name != "USB Peripherals") return;

            var ghostDevices = SelectedCategory.Items.Where(i => i.Label.Contains("[GHOST]")).ToList();
            if (ghostDevices.Count == 0)
            {
                ShowToast("No Ghosts Found", "Your system is already clean of disconnected USB traces.");
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

                ShowToast("Cleanup Complete", $"Successfully requested deletion of {ghostDevices.Count} ghost device(s). Refreshing list...");
                
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
                ShowToast("Cleanup Failed", "You must accept the Administrator prompt to delete registry keys.", isError: true);
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

            var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(0.3))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            ToastScrim.BeginAnimation(UIElement.OpacityProperty, fadeIn);

            // Animate progress bar over 3 seconds
            double targetWidth = ToastProgressTrack.ActualWidth;
            if (targetWidth <= 0) targetWidth = 300; // safe fallback

            var progressAnim = new DoubleAnimation(0, targetWidth, TimeSpan.FromSeconds(3))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
            };
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
            var btnFadeIn = new DoubleAnimation(0.3, 1, TimeSpan.FromSeconds(0.25));
            ToastDismissBtn.BeginAnimation(UIElement.OpacityProperty, btnFadeIn);
        }

        private void ToastDismiss_Click(object sender, RoutedEventArgs e)
        {
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromSeconds(0.25))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            fadeOut.Completed += (s, ev) =>
            {
                ToastScrim.Visibility = Visibility.Collapsed;
            };
            ToastScrim.BeginAnimation(UIElement.OpacityProperty, fadeOut);
        }
    }
}