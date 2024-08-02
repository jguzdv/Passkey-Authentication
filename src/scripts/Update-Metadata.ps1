[CmdletBinding()]
param (
    [string]$FidoMetadataUrl = 'https://mds3.fidoalliance.org/',
    [string]$CommunityMetadataUrl = 'https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json',
    [string]$OutputPath = './wwwroot/aaguid/'
)

begin {
    function ConvertFrom-UrlBase64 {
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
            [string]$InputString
        )

        process {
            try {
                Write-Information "Converting $($InputString.Length) characters from URL base64";
                $base64 = $InputString.Replace('-', '+').Replace('_', '/');

                $paddingNeeded = (4 - ($base64.Length % 4)) % 4;
                Write-Information "Padding needed: $paddingNeeded";

                $base64 = $base64.PadRight($base64.Length + $paddingNeeded, '=');

                Write-Information "Padded Length: $($base64.Length)"
                $bytes = [System.Convert]::FromBase64String($base64);

                return [Text.Encoding]::UTF8.GetString($bytes);
            } catch {
                Write-Error "Failed to convert from URL base64: $_"
            }
        }
    }

    function Split-JwtMetadata {
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [string]$InputString
        )

        return @($InputString.Split(".", 3, "TrimEntries"));
    }

    function Get-FidoMetadata {
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [string]$MetadataUrl
        )

        $MetadataResponse = Invoke-WebRequest -Uri $MetadataUrl
        return [Text.Encoding]::ASCII.GetString($MetadataResponse.Content);
    }

    function Write-FidoAAGuidFile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$OutputPath,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $MetadataEntry
        )

        begin {
            if(!(Test-Path $OutputPath)) {
                New-Item -Path $OutputPath -ItemType "Directory" | Out-Null ;
            }
        }

        process {
            Set-Content -Path "$OutputPath\$($MetadataEntry.AaGuid).json" -Value ($MetadataEntry.metadataStatement | ConvertTo-Json -Depth 100);
        }
    }

    function Write-CommunityAAGuidFile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$OutputPath,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $MetadataEntry
        )

        begin {
            if(!(Test-Path $OutputPath)) {
                New-Item -Path $OutputPath -ItemType "Directory" | Out-Null ;
            }
        }

        process {
            Set-Content -Path "$OutputPath\$($MetadataEntry.AaGuid).json" -Value ($MetadataEntry.Value | ConvertTo-Json -Depth 100);
        }
    }

    function Invoke-FidoMetadataUpdate {
        param(
            [Parameter(Mandatory = $true)]
            [string]$MetadataUrl,
            [Parameter(Mandatory = $true)]
            [string]$OutputPath
        )

        $Metadata = Get-FidoMetadata $MetadataUrl;
        $Header, $Payload, $Signature = Split-JwtMetadata $Metadata

        $HeaderObject = ConvertFrom-UrlBase64 $Header | ConvertFrom-Json;
        $MetadataObject = ConvertFrom-UrlBase64 $Payload | ConvertFrom-Json;
        $SignatureBytes = ConvertFrom-UrlBase64 $Signature;

        # TODO: Validate signature

        $MetadataObject.entries | where { $_.aaguid } | Write-FidoAAGuidFile -OutputPath $OutputPath;
    }

    function Invoke-CommunityMetadataUpdate {
        param(
            [Parameter(Mandatory = $true)]
            [string]$MetadataUrl,
            [Parameter(Mandatory = $true)]
            [string]$OutputPath
        )

        $Metadata = Invoke-WebRequest -Uri $MetadataUrl;
        $MetadataObject = $Metadata.Content | ConvertFrom-Json;

        $MetadataObject.PSObject.Properties | % { [PSCustomObject]@{ AaGuid = $_.Name; Value = $_.Value } } | Write-CommunityAAGuidFile -OutputPath $OutputPath;
    }
}

process {
    try {
        Invoke-FidoMetadataUpdate -MetadataUrl $FidoMetadataUrl -OutputPath "$OutputPath/fido"
    } catch {
        Write-Error "Failed to update fido metadata: $_"
    }

    try {
        Invoke-CommunityMetadataUpdate -MetadataUrl $CommunityMetadataUrl -OutputPath "$OutputPath/community"
    } catch {
        Write-Error "Failed to update community metadata: $_"
    }
}

#$Header
#$Payload
#$Signature

