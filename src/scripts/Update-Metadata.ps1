[CmdletBinding()]
param (
    [string]$MetadataUrl = 'https://mds3.fidoalliance.org/',
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

    function Write-AAGuidFile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$OutputPath,
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            $MetadataEntry
        )

        begin {
            New-Item -Path $OutputPath -ItemType "Directory" | Out-Null ;
        }

        process {
            Set-Content -Path "$OutputPath\$($MetadataEntry.AaGuid).json" -Value ($MetadataEntry.metadataStatement | ConvertTo-Json -Depth 10);
        }
    }

    function Invoke-MetadataUpdate {
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

        $MetadataObject.entries | where { $_.aaguid } | Write-AAGuidFile -OutputPath $OutputPath;
    }
}

process {
    Invoke-MetadataUpdate -MetadataUrl $MetadataUrl -OutputPath $OutputPath
}

#$Header
#$Payload
#$Signature

