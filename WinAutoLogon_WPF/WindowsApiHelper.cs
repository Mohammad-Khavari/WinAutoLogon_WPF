using System.Runtime.InteropServices;

/// <summary>
/// A helper class that provides simplified access to Windows Local Security Authority (LSA)
/// functions for managing private data and secrets in the system policy.
/// </summary>
public class WindowsApiHelper
{
  #region Structures

  /// <summary>
  /// Defines object attributes for LSA policy operations.
  /// This structure is required by Windows API but is initialized with default values internally.
  /// </summary>
  [StructLayout(LayoutKind.Sequential)]
  private struct LSA_OBJECT_ATTRIBUTES
  {
    public int Length;              // Size of the structure
    public IntPtr RootDirectory;    // Not used, always null
    public IntPtr ObjectName;       // Not used, always null
    public uint Attributes;         // Object attributes, typically 0
    public IntPtr SecurityDescriptor; // Security descriptor, not used here
    public IntPtr SecurityQualityOfService; // Quality of service, not used here
  }

  /// <summary>
  /// Represents a Unicode string structure used by LSA functions.
  /// Contains length information and a pointer to the string buffer.
  /// </summary>
  [StructLayout(LayoutKind.Sequential)]
  private struct LSA_UNICODE_STRING
  {
    public ushort Length;           // Length of string in bytes (chars * 2)
    public ushort MaximumLength;    // Maximum length of buffer in bytes
    public IntPtr Buffer;          // Pointer to the Unicode string data
  }

  #endregion

  #region Windows API Imports

  /// <summary>
  /// Opens an LSA policy handle for the specified system.
  /// </summary>
  [DllImport("advapi32.dll", SetLastError = true)]
  private static extern uint LsaOpenPolicy(
      ref LSA_UNICODE_STRING systemName,      // Target system name (null for local)
      ref LSA_OBJECT_ATTRIBUTES objectAttributes, // Object attributes (typically empty)
      uint desiredAccess,                    // Requested access rights
      out IntPtr policyHandle);             // Returns the opened policy handle

  /// <summary>
  /// Retrieves private data stored under a specified key in the LSA.
  /// </summary>
  [DllImport("advapi32.dll", SetLastError = true)]
  private static extern uint LsaRetrievePrivateData(
      IntPtr policyHandle,                  // Open policy handle
      ref LSA_UNICODE_STRING keyName,       // Name of the key to retrieve
      out IntPtr privateData);             // Returns pointer to retrieved data

  /// <summary>
  /// Stores private data under a specified key in the LSA.
  /// Passing null as privateData removes the existing secret.
  /// </summary>
  [DllImport("advapi32.dll", SetLastError = true)]
  private static extern uint LsaStorePrivateData(
      IntPtr policyHandle,                  // Open policy handle
      ref LSA_UNICODE_STRING keyName,       // Name of the key to store under
      ref LSA_UNICODE_STRING privateData); // Data to store (or null to remove)

  /// <summary>
  /// Closes an open LSA handle, freeing associated resources.
  /// </summary>
  [DllImport("advapi32.dll", SetLastError = true)]
  private static extern uint LsaClose(IntPtr objectHandle); // Handle to close

  /// <summary>
  /// Converts an LSA NT status code to a Windows error code.
  /// </summary>
  [DllImport("advapi32.dll", SetLastError = true)]
  private static extern uint LsaNtStatusToWinError(uint status); // NT status to convert

  // Add this new import for freeing LSA-allocated memory
  [DllImport("advapi32.dll", SetLastError = true)]
  private static extern uint LsaFreeMemory(IntPtr buffer);
  #endregion

  #region Constants

  /// <summary>
  /// Indicates successful completion of an LSA operation (0x00000000).
  /// </summary>
  private const uint STATUS_SUCCESS = 0x00000000;

  /// <summary>
  /// Access right to retrieve private information (0x00000004).
  /// </summary>
  private const uint POLICY_GET_PRIVATE_INFORMATION = 0x00000004;

  /// <summary>
  /// Access right to create secrets (0x00000008).
  /// </summary>
  private const uint POLICY_CREATE_SECRET = 0x00000008;

  #endregion

  #region Public Methods

  /// <summary>
  /// Opens a policy handle for the specified system with rights to manage private data.
  /// </summary>
  /// <param name="systemName">Target system name (null for local system)</param>
  /// <param name="policyHandle">Output parameter receiving the opened handle</param>
  /// <returns>True if successful, false otherwise</returns>
  public bool OpenPolicy(string systemName, out IntPtr policyHandle)
  {
    LSA_UNICODE_STRING lsaSystemName = StringToLsaUnicodeString(systemName); // Convert system name
    LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES // Default attributes
    {
      Length = 0,             // Structure size (0 since no special attributes)
      RootDirectory = IntPtr.Zero, // No root directory
      ObjectName = IntPtr.Zero,    // No object name
      Attributes = 0,         // No special attributes
      SecurityDescriptor = IntPtr.Zero, // No security descriptor
      SecurityQualityOfService = IntPtr.Zero // No QoS
    };

    // Request access to get private info and create secrets
    uint result = LsaOpenPolicy(ref lsaSystemName, ref objectAttributes,
        POLICY_GET_PRIVATE_INFORMATION | POLICY_CREATE_SECRET,
        out policyHandle);

    FreeLsaUnicodeString(ref lsaSystemName); // Clean up allocated memory
    return result == STATUS_SUCCESS; // Return success status
  }

  /// <summary>
  /// Retrieves private data stored under the specified key.
  /// </summary>
  /// <param name="policyHandle">Open policy handle from OpenPolicy</param>
  /// <param name="keyName">Name of the key to retrieve</param>
  /// <param name="privateData">Output parameter receiving the retrieved data</param>
  /// <returns>True if successful, false otherwise</returns>
  public bool RetrievePrivateData(IntPtr policyHandle, string keyName, out string privateData)
  {
    privateData = null!; // Initialize output parameter to null
    LSA_UNICODE_STRING lsaKeyName = StringToLsaUnicodeString(keyName); // Convert key name to LSA format
    IntPtr privateDataPtr = IntPtr.Zero; // Initialize pointer for retrieved data

    // Attempt to retrieve the private data from LSA
    uint result = LsaRetrievePrivateData(policyHandle, ref lsaKeyName, out privateDataPtr);

    // Check if the call succeeded
    if (result == STATUS_SUCCESS)
    {
      // If data was returned (not null), convert it to a string
      if (privateDataPtr != IntPtr.Zero)
      {
        // Marshal the LSA_UNICODE_STRING structure from the pointer
        LSA_UNICODE_STRING lsaPrivateData = Marshal.PtrToStructure<LSA_UNICODE_STRING>(privateDataPtr);
        // Convert the buffer to a managed string (Length is in bytes, so divide by 2 for Unicode chars)
        privateData = Marshal.PtrToStringUni(lsaPrivateData.Buffer, lsaPrivateData.Length / 2);
        // Free the LSA-allocated memory (not our allocation)
        LsaFreeMemory(privateDataPtr);
      }
      // Else, privateData remains null (no data found, which is still success)
    }

    // Clean up the key name memory we allocated
    FreeLsaUnicodeString(ref lsaKeyName);

    // Return whether the operation succeeded (not whether data was found)
    return result == STATUS_SUCCESS;
  }

  /// <summary>
  /// Stores private data under the specified key. Passing null removes the secret.
  /// </summary>
  /// <param name="policyHandle">Open policy handle from OpenPolicy</param>
  /// <param name="keyName">Name of the key to store under</param>
  /// <param name="privateData">Data to store (null to remove existing data)</param>
  /// <returns>True if successful, false otherwise</returns>
  public bool StorePrivateData(IntPtr policyHandle, string keyName, string privateData)
  {
    LSA_UNICODE_STRING lsaKeyName = StringToLsaUnicodeString(keyName); // Convert key name
    LSA_UNICODE_STRING lsaPrivateData = StringToLsaUnicodeString(privateData); // Convert data

    // Store the data (or remove if privateData is null)
    uint result = LsaStorePrivateData(policyHandle, ref lsaKeyName, ref lsaPrivateData);

    FreeLsaUnicodeString(ref lsaKeyName);     // Clean up key name memory
    FreeLsaUnicodeString(ref lsaPrivateData); // Clean up data memory
    return result == STATUS_SUCCESS;          // Return success status
  }

  /// <summary>
  /// Closes an open LSA policy handle, freeing associated resources.
  /// </summary>
  /// <param name="objectHandle">Handle to close from OpenPolicy</param>
  /// <returns>True if successful, false otherwise</returns>
  public bool CloseHandle(IntPtr objectHandle)
  {
    uint result = LsaClose(objectHandle); // Close the handle
    return result == STATUS_SUCCESS;      // Return success status
  }

  #endregion

  #region Private Helper Methods

  /// <summary>
  /// Converts a managed string to an LSA_UNICODE_STRING structure.
  /// </summary>
  /// <param name="value">String to convert (null for empty structure)</param>
  /// <returns>Populated LSA_UNICODE_STRING structure</returns>
  private LSA_UNICODE_STRING StringToLsaUnicodeString(string value)
  {
    if (value == null) // Handle null case
    {
      return new LSA_UNICODE_STRING
      {
        Buffer = IntPtr.Zero,
        Length = 0,
        MaximumLength = 0
      };
    }

    int len = value.Length * 2; // Unicode chars are 2 bytes each
    IntPtr buffer = Marshal.StringToHGlobalUni(value); // Allocate and copy string
    return new LSA_UNICODE_STRING
    {
      Buffer = buffer,           // Pointer to string data
      Length = (ushort)len,      // Current length in bytes
      MaximumLength = (ushort)(len + 2) // Max length including null terminator
    };
  }

  /// <summary>
  /// Frees memory allocated for an LSA_UNICODE_STRING structure.
  /// </summary>
  /// <param name="lsaString">Structure to free</param>
  private void FreeLsaUnicodeString(ref LSA_UNICODE_STRING lsaString)
  {
    if (lsaString.Buffer != IntPtr.Zero) // If buffer was allocated
    {
      Marshal.FreeHGlobal(lsaString.Buffer); // Free the memory
      lsaString.Buffer = IntPtr.Zero;        // Clear the pointer
    }
  }

  #endregion
}