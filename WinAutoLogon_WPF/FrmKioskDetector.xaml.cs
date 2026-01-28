using Auto_Logon;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace WinAutoLogon_WPF
{
  /// <summary>
  /// Interaction logic for FrmKioskDetector.xaml
  /// </summary>
  public partial class FrmKioskDetector : Window
  {
    Button? btnActiveInactiveKiosk;
    public FrmKioskDetector()
    {
      InitializeComponent();
    }

    private void FrmKioDetector_Load(object sender, EventArgs e)
    {
      OnLoad();
    }

    private async void OnLoad()
    {
      Cursor = Cursors.Wait; //System.Windows.Forms.Cursors.WaitCursor;
      btnActiveInactiveKiosk = new Button();
      try
      {

        var result = await Task.Run(() => KioskDetector.Detect());

        //var sb = new StringBuilder()
        //  .AppendLine($"Custom shell override: {result.HasCustomShellOverride}")
        //  .AppendLine($"Effective shell      : {result.EffectiveShell ?? "(net set)"}")
        //  .AppendLine($"Shell source         : {result.ShellSource ?? "(n/a)"}")
        //  .AppendLine($"Assigned Access (koisk) : {result.AssignedAccessConfigured}")
        //  .AppendLine($"Shell Launcher       : {result.ShellLauncherConfigured}")
        //  .AppendLine()
        //  .AppendLine(result.Notes ?? string.Empty);

        //MessageBox.Show(this, sb.ToString(), "Kiosk Mode Detection", MessageBoxButtons.OK,MessageBoxIcon.Information );

        lblSource.Content = result.ShellSource ?? "(n/a)";
        lblCustom.Content = result.HasCustomShellOverride ? "Active" : "Inactive";
        lblShell.Content = result.EffectiveShell ?? "(not set)";
        lblAssigned.Content = result.AssignedAccessConfigured ? "Enabled" : "Disabled";
        lblShellLuncher.Content = result.ShellLauncherConfigured ? "Enabled" : "Disabled";
      }
      catch (Exception ex)
      {
        MessageBox.Show(this, "Detection failed: \n\r" + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
      }
      finally
      {
        Cursor = Cursors.Arrow; //System.Windows.Forms.Cursors.Default;
        lblSource.Foreground = Brushes.Black; //new SolidColorBrush(Colors.Black);
        lblCustom.Foreground = lblCustom.Content.ToString()?.Contains("Active") == true ? Brushes.LightGreen : Brushes.Red;
        lblShell.Foreground = Brushes.Blue;//Color.Blue;
        lblAssigned.Foreground = Brushes.Orange;
        lblShellLuncher.Foreground = Brushes.Orange;

        if (this.FindName("btnActiveInactive") as Button == null)
        {
          // Create button
          Button btnActiveInactiveKiosk = new()
          {
            // Position relative to lblCustom (using Margin inside a Grid)
            Width = 99,
            Height = 22,
            Margin = new Thickness(
                 -180 ,   // Left offset
                lblCustom.Margin.Top - 115, 0, 0),                            // Top offset

            // Set text (Content in WPF)
            Content = (lblCustom.Content?.ToString()?.Contains("Active") == true) ? "Disable" : "Enable"
          };
          // Event handler
          btnActiveInactiveKiosk.Click += (s, e) => ActivateDeactivate();
          // Name
          btnActiveInactiveKiosk.Name = "btnActiveInactive";
          // Add to Grid (or other container)
          MainGrid.Children.Add(btnActiveInactiveKiosk);

        }
        else
        {
          bool isActive = lblCustom.Content.ToString()?.Contains("Active") == true;
          btnActiveInactiveKiosk.Margin = new Thickness(lblCustom.Margin.Right + 6, lblCustom.Margin.Top - 5, 0, 0); //new Point(lblCustom.Right + 6, lblCustom.Top - 5);
          Panel.SetZIndex(btnActiveInactiveKiosk, 10); //btnActiveInactiveKiosk.BringToFront();
          btnActiveInactiveKiosk.Content = isActive ? "Disable" : "Enable";
        }
      }
    }

    private void ActivateDeactivate()
    {
      try
      {
        bool usecurrentUser = false;
        bool deactivate = false;
        bool? resutl = DialogResult;
        if (lblCustom.Content.ToString()?.Contains("Active") == true)
        {
          resutl = MessageBox.Show("Do you want to deactive the Kiosk mode for this user?", "Which User?", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;
           
        }
        else
        {
          resutl = MessageBox.Show("Do you want to active the Kiosk mode only for this user?", "Which User?", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
        }


        if (resutl == DialogResult)
        {
          usecurrentUser = true;
          deactivate = true;
        }
        RegistryKey root = usecurrentUser ? Registry.CurrentUser : Registry.LocalMachine;

        using (var key = root.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", writable: true))
        {
          if (key != null && key.GetValue("Shell") != null && deactivate)
          {
            bool shellVal = (key?.GetValue("Shell")?.ToString() ?? "").Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
            if (shellVal)
            {
               resutl = MessageBox.Show($"Shell has already a value {key?.GetValue("Shell")}, Do you want to change it?", "Info", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;
              if (resutl == DialogResult)
              {
                ShowInput();
              }
            }
            else
            {
             key?.DeleteValue("Shell");
              OnLoad();
            }
          }
          else
          {
            ShowInput();
          }
        }

      }
      catch (Exception ex)
      {
        MessageBox.Show($"Error happened!\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
      }
    }

    private async Task AddShellValue()
    {
      try
      {
        RegistryKey root = true ? Registry.CurrentUser : Registry.LocalMachine;

        using (var key = root.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", writable: true))
        {

          key?.SetValue("Shell", txtShellPath.Text);
          lblMsgG.Visibility = Visibility.Visible;
          await Task.Delay(2000);
          lblMsgG.Visibility = Visibility.Visible;
        }
      }
      catch (Exception ex)
      {
        MessageBox.Show($"Error happened while adding registery value\n{ex.Message}", "Registery Error", MessageBoxButton.OK, MessageBoxImage.Error);

      }
      finally
      {
        txtShellPath.Text = string.Empty;
        txtShellPath.Visibility = Visibility.Hidden;
        btnShellOK.Visibility = Visibility.Hidden;
        OnLoad();
      }
    }

    private void ShowInput()
    {
      btnShellOK.Visibility = Visibility.Visible;
      txtShellPath.Visibility = Visibility.Visible;
      lblSource.Visibility = Visibility.Collapsed;
      txtShellPath.Focus();
      btnShellOK.Click += async (e, s) => await AddShellValue();
    }

    private void Exit(object sender, RoutedEventArgs e)
    {
      this.Close();
    }
  }
}
