#Requires -Version 3.0

Param(
   <# [string] [Parameter(Mandatory=$true)] $ResourceGroupLocation,#>
    [string] $ResourceGroupName = 'AzureFIARMTMPV1',
    [switch] $UploadArtifacts,
    [string] $StorageAccountName,
    [string] $StorageContainerName = $ResourceGroupName.ToLowerInvariant() + '-stageartifacts',
    [string] $TemplateFile = 'WebSite.json',
    [string] $TemplateParametersFile = 'WebSite.parameters.json',
    [string] $ArtifactStagingDirectory = '.',
    [string] $DSCSourceFolder = 'DSC',
    [switch] $ValidateOnly,
    [string] $CommonName = 'azurefi'
    #[string] $ClientId,
    #[string] $ClientSecret,
    #[string] $TenantId
)

try {
    [Microsoft.Azure.Common.Authentication.AzureSession]::ClientFactory.AddUserAgent("VSAzureTools-$UI$($host.name)".replace(' ','_'), '3.0.0')
} catch { }

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

function GetCredentials{
    param($ClientId,$ClientSecret) 
    $securePassword = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
    $psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $securePassword
    return $psCredential
}
#Gets the UniqueHash for obtaining functionapp name.
function GetUniqueHash{
    param($ClientId,$TenantId,$SubscriptionId)
    $hash = [System.Text.StringBuilder]::new()
    $md5provider = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
    [byte[]] $bytes = $md5provider.ComputeHash([System.Text.UTF8Encoding]::UTF8.GetBytes($ClientId + $TenantId + $SubscriptionId))
    Foreach ($byte in $bytes)
    {
        $hash.Append($byte.ToString("x2"))
    }
    return ($hash.ToString().Substring(0,24))
}

function Format-ValidationOutput {
    param ($ValidationOutput, [int] $Depth = 0)
    Set-StrictMode -Off
    return @($ValidationOutput | Where-Object { $_ -ne $null } | ForEach-Object { @('  ' * $Depth + ': ' + $_.Message) + @(Format-ValidationOutput @($_.Details) ($Depth + 1)) })
}
function Main{
    param($ClientId,$TenantId,$ClientSecret,$SubscriptionId)
    try
    {
        $psCredential = GetCredentials -ClientId $ClientId -ClientSecret $ClientSecret
        Connect-AzureRmAccount -ServicePrincipal -Credential $psCredential -TenantId $TenantId

        if(!(Get-AzureRmWebApp -ResourceGroupName $ResourceGroupName -Name $websiteName -ErrorAction Stop).DefaultHostName){}
        else
        {
             Remove-AzureRmWebApp -ResourceGroupName $ResourceGroupName -Name $websiteName
        }
    }
    catch [Microsoft.Rest.Azure.CloudException]
    {
        Write-Host "There is no WebApp in azure with the given WebAppName."
    }
    catch
    {
       Write-Host $_.Exception.Message
    }
    try
    {
       [string]$uniqueHash = (GetUniqueHash -ClientId $ClientId -TenantId $TenantId -SubscriptionId $SubscriptionId)
       $uniqueHash=$uniqueHash.Substring(0,24)
       [string]$functionAppName = $CommonName + $uniqueHash
       if(!(Get-AzureRmWebApp -ResourceGroupName $ResourceGroupName -Name $functionAppName -ErrorAction Stop).DefaultHostName){}
       else
       {
	         Remove-AzureRmWebApp -ResourceGroupName $ResourceGroupName -Name $functionAppName
       }
    }   
    catch [Microsoft.Rest.Azure.CloudException]
    {
       Write-Host "There is no FunctionApp in azure with the given FunctionAppName."  
    }
    catch
    {
       Write-Host $_.Exception.Message
    }
    try
    {
       if(!(Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName -ErrorAction SilentlyContinue)[0].Value){}
       else
       {
           $primaryKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName -ErrorAction Stop)[0].Value 
           $storageContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $primaryKey -ErrorAction Stop
           #$storageContext = New-AzureStorageContext -ConnectionString ("DefaultEndpointsProtocol=https;AccountName=" + $storageAccountName + ";AccountKey=" + $primaryKey)
           if(!(Get-AzureStorageContainer -Context $storageContext -Name $StorageContainerName -ErrorAction Stop).Name){}
           else
           {
                Remove-AzureStorageContainer -Context $storageContext -Name $StorageContainerName -ErrorAction SilentlyContinue
           }
       }
    }
    catch [Microsoft.Rest.Azure.CloudException]
    {
        Write-Host "Check for valid resourceroupname and storageaccountname."
    }
    catch [System.Management.Automation.RuntimeException]
    {
        Write-Host "Check for valid resourceroupname,storageaccountname,storageaccountkey,storagecontext and container name."  
    }
    catch [Microsoft.WindowsAzure.Commands.Storage.Common.ResourceNotFoundException]
    {
        Write-Host $_.Exception.Message
        Write-Host "The container name is not valid.Please check for a valid container name."
    }
    catch [System.FormatException]
    {
        Write-Host $_.Exception.Message
        Write-Host "Check whether the separation of storage key is done while extracting the storage key.Or else check for valid variable assigned for the parameter StorageAccountKey"
    }
    catch
    {
        Write-Host $_.Exception.Message
    }
}
$OptionalParameters = New-Object -TypeName Hashtable
$TemplateFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $TemplateFile))
$TemplateParametersFile = ([System.IO.Path]::GetFullPath($TemplateParametersFile))

if ($UploadArtifacts) {
    # Convert relative paths to absolute paths if needed
    $ArtifactStagingDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $ArtifactStagingDirectory))
    $DSCSourceFolder = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $DSCSourceFolder))

    # Parse the parameter file and update the values of artifacts location and artifacts location SAS token if they are present
    $JsonParameters = Get-Content $TemplateParametersFile -Raw | ConvertFrom-Json
    if (($JsonParameters | Get-Member -Type NoteProperty 'parameters') -ne $null) {
        $JsonParameters = $JsonParameters.parameters
    }
    $ArtifactsLocationName = '_artifactsLocation'
    $ArtifactsLocationSasTokenName = '_artifactsLocationSasToken'
    $OptionalParameters[$ArtifactsLocationName] = $JsonParameters | Select -Expand $ArtifactsLocationName -ErrorAction Ignore | Select -Expand 'value' -ErrorAction Ignore
    $OptionalParameters[$ArtifactsLocationSasTokenName] = $JsonParameters | Select -Expand $ArtifactsLocationSasTokenName -ErrorAction Ignore | Select -Expand 'value' -ErrorAction Ignore

    # Create DSC configuration archive
    if (Test-Path $DSCSourceFolder) {
        $DSCSourceFilePaths = @(Get-ChildItem $DSCSourceFolder -File -Filter '*.ps1' | ForEach-Object -Process {$_.FullName})
        foreach ($DSCSourceFilePath in $DSCSourceFilePaths) {
            $DSCArchiveFilePath = $DSCSourceFilePath.Substring(0, $DSCSourceFilePath.Length - 4) + '.zip'
            Publish-AzureRmVMDscConfiguration $DSCSourceFilePath -OutputArchivePath $DSCArchiveFilePath -Force -Verbose
        }
    }

    # Create a storage account name if none was provided
    if ($StorageAccountName -eq '') {
        $StorageAccountName = 'stage' + ((Get-AzureRmContext).Subscription.SubscriptionId).Replace('-', '').substring(0, 19)
    }
    
    $JsonParameters = Get-Content $TemplateParametersFile -Raw| ConvertFrom-Json
    $websiteName = $JsonParameters.parameters.webSiteName.value
    $ClientId = $JsonParameters.parameters.clientID.value
    $ClientSecret = $JsonParameters.parameters.clientSecretKey.value
    $TenantId = $JsonParameters.parameters.tenantID.value
    $SubscriptionId = (Get-AzureRmContext).Subscription.SubscriptionId
    
    Main -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -SubscriptionId $SubscriptionId
    
    $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
    
    # Create the storage account if it doesn't already exist
  <#  if ($StorageAccount -eq $null) {
        $StorageResourceGroupName = 'ARM_Deploy_Staging'
        New-AzureRmResourceGroup -Location "$ResourceGroupLocation" -Name $StorageResourceGroupName -Force
        $StorageAccount = New-AzureRmStorageAccount -StorageAccountName $StorageAccountName -Type 'Standard_LRS' -ResourceGroupName $StorageResourceGroupName -Location "$ResourceGroupLocation"
    }#>

    # Generate the value for artifacts location if it is not provided in the parameter file
    if ($OptionalParameters[$ArtifactsLocationName] -eq $null) {
        $OptionalParameters[$ArtifactsLocationName] = $StorageAccount.Context.BlobEndPoint + $StorageContainerName
    }
    
    # Copy files from the local storage staging location to the storage account container
    New-AzureStorageContainer -Name $StorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1

    while(!(Get-AzureStorageContainer -Name $StorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue))
    {
        Start-Sleep -Seconds 5
        New-AzureStorageContainer -Name $StorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue
    }

    $ArtifactFilePaths = Get-ChildItem $ArtifactStagingDirectory -Recurse -File | ForEach-Object -Process {$_.FullName}
    foreach ($SourcePath in $ArtifactFilePaths) {
        Set-AzureStorageBlobContent -File $SourcePath -Blob $SourcePath.Substring($ArtifactStagingDirectory.length + 1) `
            -Container $StorageContainerName -Context $StorageAccount.Context -Force
    }

    # Generate a 4 hour SAS token for the artifacts location if one was not provided in the parameters file
    if ($OptionalParameters[$ArtifactsLocationSasTokenName] -eq $null) {
        $OptionalParameters[$ArtifactsLocationSasTokenName] = ConvertTo-SecureString -AsPlainText -Force `
            (New-AzureStorageContainerSASToken -Container $StorageContainerName -Context $StorageAccount.Context -Permission r -ExpiryTime (Get-Date).AddHours(4))
    }
}

# Create or update the resource group using the specified template file and template parameters file
<#New-AzureRmResourceGroup -Name $ResourceGroupName -Location $ResourceGroupLocation -Verbose -Force#>

if ($ValidateOnly) {
    $ErrorMessages = Format-ValidationOutput (Test-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName `
                                                                                  -TemplateFile $TemplateFile `
                                                                                  -TemplateParameterFile $TemplateParametersFile `
                                                                                  @OptionalParameters)
    if ($ErrorMessages) {
        Write-Output '', 'Validation returned the following errors:', @($ErrorMessages), '', 'Template is invalid.'
    }
    else {
        Write-Output '', 'Template is valid.'
    }
}
else {
   $result =  New-AzureRmResourceGroupDeployment -Name ((Get-ChildItem $TemplateFile).BaseName + '-' + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')) `
                                       -ResourceGroupName $ResourceGroupName `
                                       -TemplateFile $TemplateFile `
                                       -TemplateParameterFile $TemplateParametersFile `
                                       @OptionalParameters `
                                       -Force -Verbose `
                                       -ErrorVariable ErrorMessages
Write-Output '', 'result:', @($result)
    if ($ErrorMessages) {
        Write-Output '', 'Template deployment returned the following errors:', @(@($ErrorMessages) | ForEach-Object { $_.Exception.Message.TrimEnd("`r`n") })
    }
}
