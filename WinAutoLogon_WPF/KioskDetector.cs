using Microsoft.Win32;
using System.Management;
using System.Windows;
//using System.Windows.Forms;

namespace Auto_Logon
{
  public static class KioskDetector
  {
    public static Result Detect()
    {
      // 1) Check Winlogon shell overrides (classic kiosk)
      string? effectiveShell = null;
      string? shellSource = null;
      bool customShell = false;

      var candidatePaths = new[]
      {
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System",
                @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System",
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            };

      foreach (var path in candidatePaths)
      {
        var value = Registry.GetValue(path, "Shell", null) as string;
        if (!string.IsNullOrWhiteSpace(value))
        {
          effectiveShell = value?.Trim();
          shellSource = path;
          break;
        }
      }

      if (!string.IsNullOrEmpty(effectiveShell))
      {
        var exe = (effectiveShell ?? string.Empty).Split(new[] { ' ' }, 2)[0].Trim('"');
        customShell = !exe.EndsWith("explorer.exe", StringComparison.OrdinalIgnoreCase);
      }

      // 2) Assigned Access (Kiosk) via MDM bridge
      bool assignedAccess = false;
      try
      {
        var scope = new ManagementScope(@"\\.\root\cimv2\mdm\dmmap");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT Configuration, KioskModeApp FROM MDM_AssignedAccess"));
        foreach (ManagementObject mo in searcher.Get().Cast<ManagementObject>())
        {
          var cfg = mo["Configuration"] as string;
          var kiosk = mo["KioskModeApp"] as string;
          if (!string.IsNullOrEmpty(cfg) || !string.IsNullOrEmpty(kiosk))
          {
            assignedAccess = true;
            break;
          }
        }
      }
      catch (ManagementException) { }
      catch (UnauthorizedAccessException) { }

      // 3) Shell Launcher (Enterprise/Education/IoT)
      bool shellLauncher = false;
      try
      {
        var scope2 = new ManagementScope(@"\\.\root\standardcimv2\embedded");
        scope2.Connect();
        using var searcher2 = new ManagementObjectSearcher(scope2, new ObjectQuery("SELECT Shell FROM WESL_UserSetting"));

        foreach (ManagementObject mo in searcher2.Get().Cast<ManagementObject>())
        {
          var shell = mo["Shell"] as string;
          if (!string.IsNullOrEmpty(shell))
          {
            shellLauncher = true;
            break;
          }
        }
      }

      catch (ManagementException mex) when (mex.ErrorCode == ManagementStatus.InvalidClass)
      {
        // Class not available on this edition of Windows      
      }
      catch (ManagementException mex) when (mex.ErrorCode == ManagementStatus.AccessDenied)
      {
        // Current user has not right to query the namespace      
      }
      catch (UnauthorizedAccessException)
      {
        // Current user has not right to query the namespace
      }
      catch (ManagementException mex)
      {
        MessageBox.Show(mex.Message, "Management Exception", MessageBoxButton.OK, MessageBoxImage.Error);
      }


      return new Result(
          customShell,
          effectiveShell ?? string.Empty,
          shellSource ?? string.Empty,
          assignedAccess,
          shellLauncher,
          "Note: Assigned Access / Shell Launcher usually don’t change Winlogon Shell; use WMI for those checks.");
    }
  }

  public sealed class Result
  {
    public bool HasCustomShellOverride { get; private set; }
    public string EffectiveShell { get; private set; }
    public string ShellSource { get; private set; }
    public bool AssignedAccessConfigured { get; private set; }
    public bool ShellLauncherConfigured { get; private set; }
    public string Notes { get; private set; }

    public Result(
        bool hasCustomShellOverride,
        string effectiveShell,
        string shellSource,
        bool assignedAccessConfigured,
        bool shellLauncherConfigured,
        string notes)
    {
      HasCustomShellOverride = hasCustomShellOverride;
      EffectiveShell = effectiveShell;
      ShellSource = shellSource;
      AssignedAccessConfigured = assignedAccessConfigured;
      ShellLauncherConfigured = shellLauncherConfigured;
      Notes = notes;
    }
  }
}